package bizlogic

import (
	. "TLSAutomate/internal"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/Al2Klimov/FUeL.go"
	log "github.com/sirupsen/logrus"
	"runtime"
	"sync"
	"time"
)

type Config struct {
	Inputs struct {
		Traefik []struct {
			AcmeJson string `yaml:"acme_json"`
		} `yaml:"traefik"`
	} `yaml:"inputs"`
	Ports struct {
		Tcp []uint16 `yaml:"tcp"`
		Udp []uint16 `yaml:"udp"`
	} `yaml:"ports"`
	services map[string]struct{}
	Records  Record `yaml:"records"`
	Outputs  struct {
		Debug bool `yaml:"debug"`
		DeSec []struct {
			Token string `yaml:"token"`
		} `yaml:"desec"`
	} `yaml:"outputs"`
}

func (c *Config) Services() map[string]struct{} {
	if c.services == nil {
		for _, proto := range protocols {
			if proto.getPorts(c) != nil {
				c.services = map[string]struct{}{}
				for _, proto := range protocols {
					for _, port := range proto.getPorts(c) {
						c.services[fmt.Sprintf("_%d._%s", port, proto.name)] = struct{}{}
					}
				}

				return c.services
			}
		}

		c.services = map[string]struct{}{}
		for _, proto := range protocols {
			c.services[fmt.Sprintf("*._%s", proto.name)] = struct{}{}
		}
	}

	return c.services
}

type DB struct {
	MaybeWritten OutputRecordSet
	Written      OutputRecordSet
}

type certsSet struct {
	sync.RWMutex

	certs      []*x509.Certificate
	lastUpdate time.Time
}

var concurrency = 2 * int64(runtime.GOMAXPROCS(0))

var selectors = map[uint8]func(*x509.Certificate) ([]byte, fuel.ErrorWithStack){
	0: func(cert *x509.Certificate) ([]byte, fuel.ErrorWithStack) {
		return cert.Raw, nil
	},
	1: func(cert *x509.Certificate) ([]byte, fuel.ErrorWithStack) {
		pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		return pub, fuel.AttachStackToError(err, 0)
	},
}

var matchTypes = map[uint8]func([]byte) []byte{
	0: func(cert []byte) []byte {
		return cert
	},
	1: func(cert []byte) []byte {
		sum := sha256.Sum256(cert)
		return sum[:]
	},
	2: func(cert []byte) []byte {
		sum := sha512.Sum512(cert)
		return sum[:]
	},
}

var protocols = []struct {
	name     string
	getPorts func(cfg *Config) []uint16
}{
	{"tcp", func(cfg *Config) []uint16 { return cfg.Ports.Tcp }},
	{"udp", func(cfg *Config) []uint16 { return cfg.Ports.Udp }},
}

func uniqCerts(certs []*x509.Certificate) []*x509.Certificate {
	var uniqs []*x509.Certificate

NotUniqCerts:
	for _, cert := range certs {
		for _, uniq := range uniqs {
			if cert.Equal(uniq) {
				continue NotUniqCerts
			}
		}

		uniqs = append(uniqs, cert)
	}

	return uniqs
}

func filterCerts(certs []*x509.Certificate) []*x509.Certificate {
	var filtered []*x509.Certificate
	now := time.Now()

	for _, cert := range certs {
		if now.Before(cert.NotBefore) {
			log.WithFields(describeCert(cert)).
				WithField("valid_since", cert.NotBefore).Trace("cert not valid, yet")
			continue
		}

		if now.After(cert.NotAfter) {
			log.WithFields(describeCert(cert)).WithField("valid_until", cert.NotAfter).Trace("cert expired")
			continue
		}

		{
			found := false
			for _, usage := range cert.ExtKeyUsage {
				if usage == x509.ExtKeyUsageServerAuth {
					found = true
					break
				}
			}

			if !found {
				log.WithFields(describeCert(cert)).Trace("cert may not authenticate TLS web servers")
				continue
			}
		}

		if len(cert.DNSNames) < 1 {
			log.WithFields(describeCert(cert)).Trace("cert has no DNS SANs")
			continue
		}

		if cert.IsCA {
			log.WithFields(describeCert(cert)).Trace("cert is a CA")
			continue
		}

		log.WithFields(describeCert(cert)).Trace("cert is OK")
		filtered = append(filtered, cert)
	}

	return filtered
}

func describeCert(cert *x509.Certificate) log.Fields {
	sum := md5.Sum(cert.Raw)

	return log.Fields{
		"subject": cert.Subject.String(), "ca": cert.IsCA, "sans": cert.DNSNames, "md5": hex.EncodeToString(sum[:]),
	}
}
