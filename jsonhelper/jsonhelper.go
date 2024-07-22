package jsonhelper

import (
	"encoding/json"
	"os"
)

// OpenAndDecodeDisallowUnknownFields opens the file at path and decodes it into v, disallowing unknown fields.
func OpenAndDecodeDisallowUnknownFields(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	return d.Decode(v)
}
