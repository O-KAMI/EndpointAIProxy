package state

import (
	"context"
	"database/sql"
	"errors"

	"endpointai/client/internal/contracts"
)

func (s *Store) LoadPendingCredentialRotation(ctx context.Context) (string, error) {
	var data []byte
	var size int
	err := s.db.QueryRowContext(ctx, "SELECT substr(protected_state,1,65536),length(protected_state) FROM pending_credential_rotation WHERE singleton_id=1").Scan(&data, &size)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if size > 65536 || s.p == nil {
		return "", errors.New("CONTROL_ROTATION_STATE_INVALID")
	}
	return s.p.Unprotect(data)
}

// Compare the protected plaintext inside the transaction: protection may use a
// random nonce, so ciphertext equality is not a stable compare-and-swap key.
func (s *Store) rotationMatches(ctx context.Context, tx *sql.Tx, expected string) error {
	var data []byte
	err := tx.QueryRowContext(ctx, "SELECT protected_state FROM pending_credential_rotation WHERE singleton_id=1").Scan(&data)
	if errors.Is(err, sql.ErrNoRows) && expected == "" {
		return nil
	}
	if err != nil {
		return errors.New("CONTROL_ROTATION_STATE_CHANGED")
	}
	if len(data) > 65536 {
		return errors.New("CONTROL_ROTATION_STATE_INVALID")
	}
	value, err := s.p.Unprotect(data)
	if err != nil {
		return errors.New("CONTROL_ROTATION_STATE_INVALID")
	}
	if value != expected || expected == "" {
		return errors.New("CONTROL_ROTATION_STATE_CHANGED")
	}
	return nil
}

func (s *Store) SavePendingCredentialRotation(ctx context.Context, expected, value string) error {
	if s.p == nil || value == "" || len(value) > 16384 {
		return errors.New("CONTROL_ROTATION_STATE_INVALID")
	}
	data, err := s.p.Protect(value)
	if err != nil {
		return err
	}
	defer clear(data)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.rotationMatches(ctx, tx, expected); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO pending_credential_rotation VALUES(1,?) ON CONFLICT(singleton_id) DO UPDATE SET protected_state=excluded.protected_state`, data); err != nil {
		return err
	}
	return tx.Commit()
}

// Token, transport binding, and removal of pending state share one SQLite
// commit. A concurrent recovery or changed pending record rejects the commit.
func (s *Store) CommitCredentialRotation(ctx context.Context, v contracts.CredentialRotationState) error {
	if s.p == nil || v.Pending == "" || v.PreviousToken == "" || v.Token == "" || v.Transport == "" || v.ActivatedAtUTC.IsZero() {
		return errors.New("CONTROL_ROTATION_STATE_INVALID")
	}
	token, err := s.p.Protect(v.Token)
	if err != nil {
		return err
	}
	defer clear(token)
	binding, err := s.p.Protect(v.Transport)
	if err != nil {
		return err
	}
	defer clear(binding)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.rotationMatches(ctx, tx, v.Pending); err != nil {
		return err
	}
	var old []byte
	var origin, pin sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT protected_token,server_origin,server_certificate_spki_sha256 FROM device_credential WHERE singleton_id=1`).Scan(&old, &origin, &pin); err != nil {
		return err
	}
	previous, err := s.p.Unprotect(old)
	if err != nil {
		return err
	}
	if previous != v.PreviousToken || !origin.Valid || origin.String != v.Origin || !pin.Valid || pin.String != v.Pin {
		return errors.New("CONTROL_ROTATION_CREDENTIAL_CHANGED")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE device_credential SET protected_token=?,enrolled_at_utc=? WHERE singleton_id=1`, token, format(v.ActivatedAtUTC)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_transport_state VALUES(1,?) ON CONFLICT(singleton_id) DO UPDATE SET protected_state=excluded.protected_state`, binding); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM pending_credential_rotation WHERE singleton_id=1"); err != nil {
		return err
	}
	return tx.Commit()
}
