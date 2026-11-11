// redhands-creds performs local, offline credential-store maintenance. It never
// accepts secret keys on the command line or sends them to the MCP server.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yasindce1998/redhands/pkg/credstore"
	"github.com/yasindce1998/redhands/pkg/storage"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 || (args[0] != "verify" && args[0] != "upgrade" && args[0] != "rotate" && args[0] != "migrate-targetdb") {
		return fmt.Errorf("usage: redhands-creds verify|upgrade|rotate|migrate-targetdb (stop the server and back up data first; use REDHANDS_CREDSTORE_FILE, REDHANDS_CREDSTORE_KEY, REDHANDS_CREDSTORE_NEW_KEY, REDHANDS_TARGETDB_FILE)")
	}
	path := os.Getenv("REDHANDS_CREDSTORE_FILE")
	if path == "" {
		path = "credstore.enc"
	}
	if args[0] != "migrate-targetdb" {
		if _, err := os.Stat(path); err != nil {
			return err
		}
	}
	s, err := credstore.NewStore(path, os.Getenv("REDHANDS_CREDSTORE_KEY"))
	if err != nil {
		return err
	}
	switch args[0] {
	case "verify":
		fmt.Printf("Credential store verified: %d entries\n", s.Count())
		return nil
	case "upgrade":
		return s.Upgrade()
	case "rotate":
		return s.RotateKey(os.Getenv("REDHANDS_CREDSTORE_NEW_KEY"))
	case "migrate-targetdb":
		dbPath := os.Getenv("REDHANDS_TARGETDB_FILE")
		if dbPath == "" {
			dbPath = "targetdb.json"
		}
		dbAbs, err := filepath.Abs(dbPath)
		if err != nil {
			return err
		}
		storeAbs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if dbAbs == storeAbs {
			return fmt.Errorf("target database and encrypted credential store must be different files")
		}
		if dbInfo, err := os.Stat(dbPath); err == nil {
			if storeInfo, err := os.Stat(path); err == nil && os.SameFile(dbInfo, storeInfo) {
				return fmt.Errorf("target database and credential store refer to the same file")
			}
		}
		data, err := os.ReadFile(dbPath)
		if err != nil {
			return err
		}
		// Preserve every unknown field rather than round-tripping a partial schema.
		var document map[string]json.RawMessage
		if err := json.Unmarshal(data, &document); err != nil || document == nil {
			return fmt.Errorf("invalid target database")
		}
		var records []map[string]json.RawMessage
		if err := json.Unmarshal(document["credentials"], &records); err != nil {
			return err
		}
		// Validate the complete import before changing even the encrypted store.
		seen := make(map[[4]string]string)
		for _, record := range records {
			encoded, err := json.Marshal(record)
			if err != nil {
				return err
			}
			var c targetdb.Credential
			if err := json.Unmarshal(encoded, &c); err != nil {
				return err
			}
			if record == nil || (c.Secret != "" && (c.Username == "" || c.Type == "")) {
				return fmt.Errorf("credential metadata is incomplete; source left untouched")
			}
			if c.Secret != "" {
				identity := [4]string{c.Host, c.Username, c.Domain, c.Type}
				if secret, ok := seen[identity]; ok && secret != c.Secret {
					return fmt.Errorf("conflicting secrets for the same identity; resolve duplicates before migration")
				}
				seen[identity] = c.Secret
			}
		}
		for _, record := range records {
			encoded, err := json.Marshal(record)
			if err != nil {
				return err
			}
			var c targetdb.Credential
			if err := json.Unmarshal(encoded, &c); err != nil {
				return err
			}
			if c.Secret == "" {
				continue
			}
			if c.Username == "" || c.Type == "" {
				return fmt.Errorf("credential metadata is incomplete; source left untouched")
			}
			entry := &credstore.Entry{ID: c.ID, Host: c.Host, Username: c.Username, Secret: c.Secret, Type: c.Type, Domain: c.Domain, Source: c.Source, Valid: c.Valid}
			if err := s.Add(entry); err != nil {
				return err
			}
			// Verify a separately reopened encrypted store before clearing plaintext.
			check, err := credstore.NewStore(path, os.Getenv("REDHANDS_CREDSTORE_KEY"))
			if err != nil {
				return err
			}
			found := false
			for _, saved := range check.Search("") {
				if saved.ID == entry.ID && saved.Secret == c.Secret {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("encrypted backup verification failed; source left untouched")
			}
			record["secret"] = json.RawMessage(`""`)
		}
		document["credentials"], err = json.Marshal(records)
		if err != nil {
			return err
		}
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return err
		}
		return storage.WriteFile(dbPath, encoded)
	}
	return nil
}
