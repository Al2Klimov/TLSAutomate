package main

import (
	. "TLSAutomate/internal"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"syscall"
)

const (
	exe    = "/TLSAutomate"
	config = "/TLSAutomate.yml"
)

func main() {
	SetupLogging()

	if err := run(); err != nil {
		log.WithError(err).Fatal()
	}
}

func run() error {
	if err := ioutil.WriteFile(config, []byte(os.Getenv("TLSAUTOMATE_CONFIG")), 0600); err != nil {
		return err
	}

	return syscall.Exec(exe, []string{exe, "-config", config}, os.Environ())
}
