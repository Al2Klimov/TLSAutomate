package internal

import (
	"encoding/json"
	"fmt"
	"github.com/Al2Klimov/FUeL.go"
)

type OutputRecordSet map[OutputRecord]struct{}

var (
	_ fmt.Formatter    = OutputRecordSet{}
	_ json.Marshaler   = OutputRecordSet{}
	_ json.Unmarshaler = (*OutputRecordSet)(nil)
)

func (ors OutputRecordSet) Format(f fmt.State, verb rune) {
	var orl []string
	for or := range ors {
		orl = append(orl, or.String())
	}

	fuel.FormatNonFormatter(f, verb, orl)
}

func (ors OutputRecordSet) MarshalJSON() ([]byte, error) {
	var orl []OutputRecord
	for or := range ors {
		orl = append(orl, or)
	}

	return json.Marshal(orl)
}

func (ors *OutputRecordSet) UnmarshalJSON(bytes []byte) error {
	var orl []OutputRecord
	if err := json.Unmarshal(bytes, &orl); err != nil {
		return err
	}

	*ors = OutputRecordSet{}

NextIter:
	for {
		for or := range *ors {
			delete(*ors, or)
			continue NextIter
		}

		break
	}

	for _, or := range orl {
		(*ors)[or] = struct{}{}
	}

	return nil
}
