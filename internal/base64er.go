package internal

import "encoding/json"

type Base64er string

var (
	_ json.Marshaler   = Base64er("")
	_ json.Unmarshaler = (*Base64er)(nil)
)

func (b Base64er) MarshalJSON() ([]byte, error) {
	return json.Marshal([]byte(b))
}

func (b *Base64er) UnmarshalJSON(bytes []byte) error {
	var into []byte
	err := json.Unmarshal(bytes, &into)

	if err == nil {
		*b = Base64er(into)
	}

	return err
}
