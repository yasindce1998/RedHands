package nmap

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
)

func Parse(r io.Reader) (*NmapRun, error) {
	var result NmapRun
	decoder := xml.NewDecoder(r)
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("parsing nmap XML: %w", err)
	}
	return &result, nil
}

func ParseBytes(data []byte) (*NmapRun, error) {
	var result NmapRun
	if err := xml.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing nmap XML: %w", err)
	}
	return &result, nil
}

func ParseFile(path string) (*NmapRun, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening nmap XML file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return Parse(f)
}
