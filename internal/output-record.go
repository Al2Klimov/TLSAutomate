package internal

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type OutputRecord struct {
	Record `json:",inline"`

	Service  string
	CertSpec Base64er
}

var _ fmt.Stringer = (*OutputRecord)(nil)

func (or *OutputRecord) String() string {
	return fmt.Sprintf(
		"%s. %d IN TLSA %d %d %d %s",
		or.Service, or.Ttl, or.CertUsage, or.Selector, or.MatchType,
		strings.ToUpper(hex.EncodeToString([]byte(or.CertSpec))),
	)
}
