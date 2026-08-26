package jsoncfg

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
)

// Load opens the JSON file at path and decodes it into v.
//
// Unknown fields in the JSON file will cause an error.
func Load(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.UnmarshalRead(f, v, json.RejectUnknownMembers(true))
}

// Save encodes v into JSON and saves it to the file at path.
func Save(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.MarshalWrite(f, v, jsontext.Multiline(true))
}
