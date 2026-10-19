package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// ReadDeviceID reads an existing identity without enrolling or writing state.
// An empty string with nil error means that no identity has been created.
func (s *Store) ReadDeviceID(ctx context.Context) (string, error) {
	var id string
	e := s.db.QueryRowContext(ctx, "SELECT device_id FROM client_identity WHERE singleton_id=1").Scan(&id)
	if e == sql.ErrNoRows {
		return "", nil
	}
	return id, e
}

// StateFingerprint returns component hashes of logical state in one read
// transaction. Credentials and routes must decrypt successfully but their
// plaintext never leaves this method. Use for stopped-service migration or
// restore verification: normal heartbeat/policy/config activity changes state.
// No identity is created, no schema is migrated and no cached route is trusted.
func (s *Store) StateFingerprint(ctx context.Context) (map[string]string, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	components := []struct {
		name, query     string
		protectedColumn int
	}{
		{"identity", "SELECT singleton_id,device_id,created_at_utc FROM client_identity ORDER BY singleton_id", -1},
		{"routes", "SELECT " + routeColumns + " FROM routes ORDER BY route_id", 4},
		{"credential", "SELECT protected_token,enrolled_at_utc,server_origin,server_certificate_spki_sha256 FROM device_credential ORDER BY singleton_id", 0},
		{"policy", "SELECT policy_json,signature,policy_version,server_instance_id,received_at_utc FROM cached_policy ORDER BY singleton_id", -1},
		{"operation", "SELECT operation_state,updated_at_utc,last_error_code,last_error_summary FROM client_operation_state ORDER BY singleton_id", -1},
		{"receipts", "SELECT " + receiptColumns + " FROM remote_command_receipts ORDER BY command_id", -1},
	}
	out := make(map[string]string, len(components))
	for _, component := range components {
		rows, err := tx.QueryContext(ctx, component.query)
		if err != nil {
			return nil, err
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			return nil, err
		}
		values := make([][]any, 0)
		for rows.Next() {
			row, pointers := make([]any, len(columns)), make([]any, len(columns))
			for i := range row {
				pointers[i] = &row[i]
			}
			if err = rows.Scan(pointers...); err != nil {
				rows.Close()
				return nil, err
			}
			for i, value := range row {
				if i == component.protectedColumn {
					var ciphertext []byte
					switch stored := value.(type) {
					case []byte:
						ciphertext = stored
					case string:
						ciphertext = []byte(stored)
					default:
						rows.Close()
						return nil, errors.New("protected state column has invalid type")
					}
					cleartext, decryptErr := s.p.Unprotect(ciphertext)
					if decryptErr != nil {
						rows.Close()
						return nil, decryptErr
					}
					row[i] = cleartext
				} else if bytes, ok := value.([]byte); ok {
					row[i] = string(bytes)
				}
			}
			values = append(values, row)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(struct {
			Component string
			Rows      [][]any
		}{component.name, values})
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(encoded)
		clear(encoded)
		out[component.name] = hex.EncodeToString(digest[:])
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}
