package internal

import (
	"context"
	"crypto/x509"
	"fmt"
	"github.com/Al2Klimov/FUeL.go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"strings"
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

func Unwildcard(p Provider, aRecs map[string]struct{}, orss ...*OutputRecordSet) {
	unwildcards := make(map[string]struct{}, len(aRecs))

ARecs:
	for svc := range aRecs {
		for _, ors := range orss {
			for or := range *ors {
				if svc == or.Service || strings.HasSuffix(or.Service, "."+svc) {
					continue ARecs
				}
			}
		}

		unwildcards[svc] = struct{}{}
	}

	if len(unwildcards) < 1 {
		return
	}

	wildcards := map[string]map[string]struct{}{}
	for _, ors := range orss {
		for or := range *ors {
			if strings.HasPrefix(or.Service, "*") {
				wildcards[strings.TrimPrefix(or.Service, "*")] = map[string]struct{}{}
			}
		}
	}

	logger := ProviderLog(p)
	hasImplicit := false

	for leaf := range unwildcards {
		for wildcard, leaves := range wildcards {
			if strings.HasSuffix(leaf, wildcard) {
				logger.WithFields(log.Fields{
					"service": leaf, "wildcard": "*" + wildcard,
				}).Info("implicitly covering already present service by explicitly covered wildcard")

				if strings.HasPrefix(leaf, "*") {
					leaves[leaf] = struct{}{}
				} else {
					for _, proto := range [2]string{"tcp", "udp"} {
						leaves[fmt.Sprintf("*._%s.%s", proto, leaf)] = struct{}{}
					}
				}

				hasImplicit = true
				break
			}
		}
	}

	if !hasImplicit {
		return
	}

	for _, ors := range orss {
		unwildcarded := make(OutputRecordSet, len(*ors))
		for or := range *ors {
			unwildcarded[or] = struct{}{}
			if strings.HasPrefix(or.Service, "*") {
				if leaves := wildcards[strings.TrimPrefix(or.Service, "*")]; len(leaves) > 0 {
					for leaf := range leaves {
						or.Service = leaf
						unwildcarded[or] = struct{}{}
					}
				}
			}
		}

		*ors = unwildcarded
	}
}
