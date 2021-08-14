package internal

import (
	"context"
	"crypto/x509"
	"github.com/Al2Klimov/FUeL.go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"time"
)

type Record struct {
	Ttl       uint32 `yaml:"ttl"`
	CertUsage uint8  `yaml:"cert_usage"`
	Selector  uint8  `yaml:"selector"`
	MatchType uint8  `yaml:"match_type"`
}

type Provider interface {
	Kind() string
	Number() int
	Ping(context.Context) fuel.ErrorWithStack
}

type Input interface {
	Provider

	Poll(ctx context.Context, since time.Time) ([]*x509.Certificate, time.Time, fuel.ErrorWithStack)
}

type Output interface {
	Provider

	Update(ctx context.Context, del, create OutputRecordSet) fuel.ErrorWithStack
}

type Numbered struct {
	Nr int
}

func (n Numbered) Number() int {
	return n.Nr
}

func SetupLogging() {
	log.SetLevel(log.TraceLevel)
	log.SetOutput(os.Stdout)

	if !terminal.IsTerminal(int(os.Stdout.Fd())) {
		log.SetFormatter(&log.JSONFormatter{DisableHTMLEscape: true})
	}
}

func ProviderLog(p Provider) *log.Entry {
	return log.WithFields(log.Fields{"kind": p.Kind(), "number": p.Number()})
}
