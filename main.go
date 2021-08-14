package main

import (
	. "TLSAutomate/internal"
	. "TLSAutomate/internal/business-logic"
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/Al2Klimov/DullDB"
	"github.com/Al2Klimov/FUeL.go"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"os"
	"strings"
	"syscall"
)

func main() {
	config := flag.String("config", "TLSAutomate.yml", "FILE")
	db := flag.String("db", "TLSAutomate.json", "FILE")
	flag.Parse()

	SetupLogging()

	if err := run(*config, *db); err != nil && !errors.Is(err, context.Canceled) {
		log.WithError(err).Fatal()
	}
}

func run(configFile string, db string) fuel.ErrorWithStack {
	cfg, err := loadConfig(configFile)
	if err != nil {
		return err
	}

	if err := pingDb(db); err != nil {
		return err
	}

	signalCtx, termSignal := fuel.SignalsToContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	g := fuel.NewErrorGroup(signalCtx, 0)

	g.Go(1, func(ctx context.Context) fuel.ErrorWithStack {
		return logTermSig(ctx, termSignal)
	})

	g.Go(1, func(ctx context.Context) fuel.ErrorWithStack {
		return EverythingElse(ctx, cfg, db)
	})

	return g.Wait()
}

func loadConfig(configFile string) (*Config, fuel.ErrorWithStack) {
	log.WithField("file", configFile).Debug("loading config")

	f, err := os.Open(configFile)
	if err != nil {
		return nil, fuel.AttachStackToError(err, 0)
	}
	defer func() { _ = f.Close() }()

	cfg := &Config{}

	cfg.Records.Ttl = 3600
	cfg.Records.CertUsage = 3
	cfg.Records.Selector = 1
	cfg.Records.MatchType = 1

	if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
		return nil, fuel.AttachStackToError(err, 0)
	}

	return cfg, validateConfig(cfg)
}

func pingDb(db string) fuel.ErrorWithStack {
	log.Debug("pinging database")
	return dulldb.Select(db, new(interface{}))
}

func validateConfig(cfg *Config) fuel.ErrorWithStack {
	if len(cfg.Inputs.Traefik) < 1 {
		return fuel.AttachStackToError(errors.New("no inputs given"), 0)
	}

	for i, traefik := range cfg.Inputs.Traefik {
		if strings.TrimSpace(traefik.AcmeJson) == "" {
			return fuel.AttachStackToError(fmt.Errorf("Traefik input #%d: acme.json path missing", i+1), 0)
		}
	}

	if len(cfg.Ports.Tcp) < 1 && len(cfg.Ports.Udp) < 1 {
		return fuel.AttachStackToError(errors.New("no ports given"), 0)
	}

	for _, constraint := range []struct {
		what     string
		actual   uint8
		expected []uint8
	}{
		{"cert_usage", cfg.Records.CertUsage, []uint8{1, 3}},
		{"selector", cfg.Records.Selector, []uint8{0, 1}},
		{"match_type", cfg.Records.MatchType, []uint8{0, 1, 2}},
	} {
		ok := false
		for _, ex := range constraint.expected {
			if constraint.actual == ex {
				ok = true
				break
			}
		}

		if !ok {
			return fuel.AttachStackToError(fmt.Errorf("%s must be one of %v", constraint.what, constraint.expected), 0)
		}
	}

	if len(cfg.Outputs.DeSec) < 1 && !cfg.Outputs.Debug {
		return fuel.AttachStackToError(errors.New("no outputs given"), 0)
	}

	for i, ds := range cfg.Outputs.DeSec {
		if strings.TrimSpace(ds.Token) == "" {
			return fuel.AttachStackToError(fmt.Errorf("deSEC output #%d: token missing", i+1), 0)
		}
	}

	return nil
}

func logTermSig(ctx context.Context, termSignal <-chan os.Signal) fuel.ErrorWithStack {
	<-ctx.Done()

	select {
	case sig := <-termSignal:
		if sig != nil {
			log.WithField("signal", sig).Info("terminating")
		}
	default:
	}

	return fuel.AttachStackToError(ctx.Err(), 0)
}
