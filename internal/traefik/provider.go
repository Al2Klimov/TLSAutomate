package traefik

import (
	. "TLSAutomate/internal"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/Al2Klimov/FUeL.go"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
	"path"
	"time"
)

type Traefik struct {
	Numbered

	AcmeJson string
}

var _ Input = (*Traefik)(nil)

func (*Traefik) Kind() string {
	return "Traefik"
}

func (t *Traefik) Ping(context.Context) fuel.ErrorWithStack {
	if _, err := ioutil.ReadDir(t.acmeDir()); err != nil {
		return fuel.AttachStackToError(err, 0)
	}

	_, err := os.Stat(t.AcmeJson)
	if os.IsNotExist(err) {
		err = nil
	}

	return fuel.AttachStackToError(err, 0)
}

func (t *Traefik) Poll(ctx context.Context, since time.Time) ([]*x509.Certificate, time.Time, fuel.ErrorWithStack) {
	{
		certs, ok, mt, err := t.read(since)
		if err != nil {
			return nil, time.Time{}, err
		}

		if ok {
			return certs, mt, nil
		}

		since = mt
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, time.Time{}, fuel.AttachStackToError(err, 0)
	}
	defer func() { _ = watcher.Close() }()

	if err := watcher.Add(t.acmeDir()); err != nil {
		return nil, time.Time{}, fuel.AttachStackToError(err, 0)
	}

	for {
		select {
		case <-ctx.Done():
			return nil, time.Time{}, fuel.AttachStackToError(ctx.Err(), 0)
		case err := <-watcher.Errors:
			ProviderLog(t).WithError(err).Warn("FS watch error, assuming queue overflow")
		case <-watcher.Events:
		}

		certs, ok, mt, err := t.read(since)
		if err != nil {
			return nil, time.Time{}, err
		}

		if ok {
			return certs, mt, nil
		}

		since = mt
	}
}

func (t *Traefik) read(since time.Time) ([]*x509.Certificate, bool, time.Time, fuel.ErrorWithStack) {
	f, errOp := os.Open(t.AcmeJson)
	if errOp != nil {
		if os.IsNotExist(errOp) {
			ProviderLog(t).Warn("ACME JSON file doesn't exist, assuming only temporarily")
			return nil, false, since, nil
		}

		return nil, false, time.Time{}, fuel.AttachStackToError(errOp, 0)
	}
	defer func() { _ = f.Close() }()

	st, errSt := f.Stat()
	if errSt != nil {
		return nil, false, time.Time{}, fuel.AttachStackToError(errSt, 0)
	}

	mt := st.ModTime()
	if !mt.After(since) {
		ProviderLog(t).WithFields(log.Fields{
			"mtime": mt, "since": since,
		}).Trace("ACME JSON file's mod time didn't change")
		return nil, false, since, nil
	}

	buf := &bytes.Buffer{}
	if _, errCp := io.Copy(buf, f); errCp != nil {
		return nil, false, time.Time{}, fuel.AttachStackToError(errCp, 0)
	}

	var acmeData map[string]struct {
		Certificates []struct {
			Certificate []byte `json:"certificate"`
			Key         []byte `json:"key"`
		}
	}
	if err := json.NewDecoder(buf).Decode(&acmeData); err != nil {
		ProviderLog(t).WithError(err).Warn("can't decode ACME JSON, assuming error is temporary")
		return nil, false, mt, nil
	}

	var certs []*x509.Certificate
	for _, resolver := range acmeData {
		for _, cert := range resolver.Certificates {
			cert, err := tls.X509KeyPair(cert.Certificate, cert.Key)
			if err != nil {
				ProviderLog(t).WithError(err).Warn("can't parse PEM")
				continue
			}

			if cert.Leaf == nil {
				if len(cert.Certificate) < 1 {
					ProviderLog(t).Warn("PEM doesn't contain any leaves")
				} else {
					leaf, err := x509.ParseCertificate(cert.Certificate[0])
					if err != nil {
						ProviderLog(t).WithError(err).Warn("can't parse PEM")
						continue
					}

					certs = append(certs, leaf)
				}
			} else {
				certs = append(certs, cert.Leaf)
			}
		}
	}

	return certs, true, mt, nil
}

func (t *Traefik) acmeDir() string {
	dir, _ := path.Split(t.AcmeJson)
	if dir == "" {
		dir = "."
	}

	return dir
}
