package desec

import (
	"fmt"
	"net/url"
)

type httpStatus uint16

var _ error = httpStatus(0)

func (hs httpStatus) Error() string {
	return fmt.Sprintf("HTTP status: %d", int(hs))
}

var v1 = &url.URL{
	Scheme: "https",
	Host:   "desec.io",
	Path:   "/api/v1/",
}

var v1Domains = v1.ResolveReference(&url.URL{Path: "domains/"})
