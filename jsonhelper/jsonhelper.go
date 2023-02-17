package jsonhelper

import (
	"encoding/json"
	"os"
)

func LoadAndDecodeDisallowUnknownFields(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	return d.Decode(v)
}
