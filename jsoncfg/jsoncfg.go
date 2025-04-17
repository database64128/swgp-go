package jsoncfg

import (
	"encoding/json"
	"os"
)

// Open opens the JSON file at path and decodes it into v.
//
// Unknown fields in the JSON file will cause an error.
func Open(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Save encodes v into JSON and saves it to the file at path.
func Save(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	return enc.Encode(v)
}
