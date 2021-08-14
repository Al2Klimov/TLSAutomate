package bizlogic

import (
	. "TLSAutomate/internal"
	. "TLSAutomate/internal/debug"
	. "TLSAutomate/internal/desec"
	. "TLSAutomate/internal/traefik"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"github.com/Al2Klimov/DullDB"
	"github.com/Al2Klimov/FUeL.go"
	log "github.com/sirupsen/logrus"
	"sort"
	"strings"
	"time"
)

func EverythingElse(ctx context.Context, cfg *Config, db string) fuel.ErrorWithStack {
	inputs, outputs, getBytes, hashBytes := setup(cfg)

	if err := ping(ctx, inputs, outputs); err != nil {
		return err
	}

	g := fuel.NewErrorGroup(ctx, 0)
	certsSets := make([]certsSet, len(inputs))
	certsChanged := make(chan struct{}, 1)

	log.Info("polling inputs")

	for i, in := range inputs {
		in := in
		ac := &certsSets[i]

		g.Go(1, func(ctx context.Context) fuel.ErrorWithStack {
			return poll(ctx, in, ac, certsChanged)
		})
	}

	g.Go(1, func(ctx context.Context) fuel.ErrorWithStack {
		return processUpdates(ctx, certsChanged, certsSets, outputs, inputs, db, getBytes, hashBytes, cfg)
	})

	return g.Wait()
}

func setup(cfg *Config) (
	inputs []Input, outputs []Output,
	getBytes func(*x509.Certificate) ([]byte, fuel.ErrorWithStack), hashBytes func([]byte) []byte,
) {
	getBytes = selectors[cfg.Records.Selector]
	hashBytes = matchTypes[cfg.Records.MatchType]

	for i, tr := range cfg.Inputs.Traefik {
		inputs = append(inputs, &Traefik{Numbered{i + 1}, tr.AcmeJson})
	}

	if cfg.Outputs.Debug {
		outputs = append(outputs, Debug{})
	}

	for i, ds := range cfg.Outputs.DeSec {
		outputs = append(outputs, &DeSEC{Numbered: Numbered{i + 1}, Token: ds.Token})
	}
	return
}

func ping(ctx context.Context, inputs []Input, outputs []Output) fuel.ErrorWithStack {
	log.Info("pinging I/Os")
	g := fuel.NewErrorGroup(ctx, concurrency)

	for _, in := range inputs {
		g.Go(1, in.Ping)
	}

	for _, out := range outputs {
		g.Go(1, out.Ping)
	}

	return g.Wait()
}

func poll(ctx context.Context, from Input, to *certsSet, notify chan<- struct{}) fuel.ErrorWithStack {
	var lastUpdate time.Time

	for {
		certs, currentUpdate, err := from.Poll(ctx, lastUpdate)
		if err != nil {
			return err
		}

		ProviderLog(from).WithFields(log.Fields{
			"amount": len(certs), "as_of": currentUpdate, "since": lastUpdate,
		}).Info("got new certs set from input")

		lastUpdate = currentUpdate

		to.Lock()
		to.certs = certs
		to.lastUpdate = currentUpdate
		to.Unlock()

		select {
		case notify <- struct{}{}:
		default:
		}
	}
}

func processUpdates(
	ctx context.Context, trigger <-chan struct{}, from []certsSet, to []Output, inputs []Input, db string,
	getBytes func(*x509.Certificate) ([]byte, fuel.ErrorWithStack), hashBytes func([]byte) []byte, cfg *Config,
) fuel.ErrorWithStack {
	loggedFailures := map[[sha256.Size]byte]struct{}{}
	lastHash := new([sha512.Size]byte)
	*lastHash = sha512.Sum512(nil)

	for {
		select {
		case <-ctx.Done():
			return fuel.AttachStackToError(ctx.Err(), 0)
		case <-trigger:
			certs, ok := collect(from, inputs)
			if !ok {
				break
			}

			records, ok := assemble(certs, loggedFailures, getBytes, hashBytes, cfg, lastHash)
			if !ok {
				break
			}

			if err := apply(ctx, to, db, records); err != nil {
				return err
			}
		}
	}
}

func collect(from []certsSet, inputs []Input) ([]*x509.Certificate, bool) {
	var certs []*x509.Certificate
	for i := range from {
		cs := &from[i]
		cs.RLock()

		if cs.lastUpdate == (time.Time{}) {
			cs.RUnlock()
			in := inputs[i]

			ProviderLog(in).Debug("input didn't present any certs by now - not processing, yet")
			return nil, false
		}

		certs = append(certs, cs.certs...)
		cs.RUnlock()
	}

	return certs, true
}

func assemble(
	certs []*x509.Certificate, loggedFailures map[[sha256.Size]byte]struct{},
	getBytes func(*x509.Certificate) ([]byte, fuel.ErrorWithStack),
	hashBytes func([]byte) []byte, cfg *Config, lastHash *[sha512.Size]byte,
) (OutputRecordSet, bool) {
	log.Info("processing new certs set")

	certs = filterCerts(uniqCerts(certs))
	certsBySan := map[string]*x509.Certificate{}

	for _, cert := range certs {
		for _, san := range cert.DNSNames {
			if cbs, ok := certsBySan[san]; !ok || cert.NotBefore.After(cbs.NotBefore) {
				certsBySan[san] = cert
			}
		}
	}

	records := OutputRecordSet{}
	for san, cert := range certsBySan {
		unhashed, err := getBytes(cert)
		if err != nil {
			hash := sha256.Sum256(cert.Raw)
			if _, ok := loggedFailures[hash]; !ok {
				log.WithFields(describeCert(cert)).Warn("can't get needed cert data (input fault?)")
				loggedFailures[hash] = struct{}{}
			}

			continue
		}

		hashed := hashBytes(unhashed)
		for _, proto := range protocols {
			for _, port := range proto.getPorts(cfg) {
				var service string
				if strings.HasPrefix(san, "*") {
					service = san
				} else {
					service = fmt.Sprintf("_%d._%s.%s", port, proto.name, san)
				}

				records[OutputRecord{cfg.Records, service, Base64er(hashed)}] = struct{}{}
			}
		}
	}

	{
		recordStrings := make([]string, 0, len(records))
		for rec := range records {
			recordStrings = append(recordStrings, rec.String())
		}

		sort.Strings(recordStrings)

		hash := sha512.Sum512([]byte(strings.Join(recordStrings, "\n")))
		if hash == *lastHash {
			log.Debug("all quiet on the western front")
			return nil, false
		}

		*lastHash = hash
	}

	return records, true
}

func apply(ctx context.Context, to []Output, db string, records OutputRecordSet) fuel.ErrorWithStack {
	var state DB
	if err := dulldb.Select(db, &state); err != nil {
		return err
	}

	del := OutputRecordSet{}
	create := OutputRecordSet{}

	for record := range records {
		if _, ok := state.Written[record]; !ok {
			create[record] = struct{}{}
		}
	}

	for _, ors := range [2]OutputRecordSet{state.MaybeWritten, state.Written} {
		for or := range ors {
			if _, ok := records[or]; !ok {
				del[or] = struct{}{}
			}
		}
	}

	maybeWritten := OutputRecordSet{}
	for _, ors := range [3]OutputRecordSet{state.MaybeWritten, state.Written, records} {
		for or := range ors {
			maybeWritten[or] = struct{}{}
		}
	}

	log.WithField("amount", len(records)).Info("writing records to outputs")

	if err := dulldb.Replace(db, &DB{maybeWritten, nil}); err != nil {
		return err
	}

	g := fuel.NewErrorGroup(ctx, concurrency)
	for _, out := range to {
		out := out
		g.Go(1, func(ctx context.Context) fuel.ErrorWithStack {
			err := out.Update(ctx, del, create)
			ProviderLog(out).WithField("amount", len(records)).Info("written records to output")
			return err
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	return dulldb.Replace(db, &DB{nil, records})
}
