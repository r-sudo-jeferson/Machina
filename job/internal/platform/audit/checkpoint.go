package audit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgtype"
)

const (
	checkpointStatementDomain  = "MCH-AUDIT-CHECKPOINT"
	checkpointStatementVersion = byte(1)
	maxCheckpointKeyIDLength   = 200
	minCheckpointSignatureSize = 64
	maxCheckpointSignatureSize = 256
)

var (
	ErrInvalidCheckpoint          = errors.New("invalid audit checkpoint")
	ErrInvalidCheckpointSignature = errors.New("invalid audit checkpoint signature")
)

type CheckpointAlgorithm string

const CheckpointAlgorithmECDSAP256SHA256 CheckpointAlgorithm = "ecdsa-p256-sha256"

type CheckpointDigest = [sha256.Size]byte

type CheckpointStatement struct {
	TenantID      pgtype.UUID
	CheckpointID  pgtype.UUID
	ChainSequence int64
	ChainHash     [sha256.Size]byte
	Algorithm     CheckpointAlgorithm
	KeyID         string
	SignedAt      time.Time
}

type StoredCheckpoint struct {
	TenantID        pgtype.UUID
	ID              pgtype.UUID
	ChainSequence   int64
	ChainHash       [sha256.Size]byte
	StatementDigest CheckpointDigest
	Algorithm       CheckpointAlgorithm
	KeyID           string
	Signature       []byte
	SignedAt        time.Time
}

func DigestCheckpointStatement(statement CheckpointStatement) (CheckpointDigest, error) {
	encoded, err := encodeCheckpointStatement(statement)
	if err != nil {
		return CheckpointDigest{}, err
	}
	return sha256.Sum256(encoded), nil
}

func VerifyCheckpointSignature(publicKey *ecdsa.PublicKey, stored StoredCheckpoint) error {
	if !validCheckpointPublicKey(publicKey) {
		return ErrInvalidCheckpointSignature
	}
	if err := validateStoredCheckpoint(stored); err != nil {
		return err
	}

	statement := CheckpointStatement{
		TenantID:      stored.TenantID,
		CheckpointID:  stored.ID,
		ChainSequence: stored.ChainSequence,
		ChainHash:     stored.ChainHash,
		Algorithm:     stored.Algorithm,
		KeyID:         stored.KeyID,
		SignedAt:      stored.SignedAt,
	}
	digest, err := DigestCheckpointStatement(statement)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest[:], stored.StatementDigest[:]) != 1 {
		return ErrInvalidCheckpointSignature
	}
	if !ecdsa.VerifyASN1(publicKey, digest[:], stored.Signature) {
		return ErrInvalidCheckpointSignature
	}
	return nil
}

func encodeCheckpointStatement(statement CheckpointStatement) ([]byte, error) {
	if err := validateCheckpointStatement(statement); err != nil {
		return nil, err
	}

	algorithm := string(statement.Algorithm)
	capacity := len(checkpointStatementDomain) + 2 + 16 + 16 + 8 + sha256.Size + 2 + len(algorithm) + 2 + len(statement.KeyID) + 8
	encoded := bytes.NewBuffer(make([]byte, 0, capacity))
	encoded.WriteString(checkpointStatementDomain)
	encoded.WriteByte(0)
	encoded.WriteByte(checkpointStatementVersion)
	encoded.Write(statement.TenantID.Bytes[:])
	encoded.Write(statement.CheckpointID.Bytes[:])
	if err := binary.Write(encoded, binary.BigEndian, uint64(statement.ChainSequence)); err != nil {
		return nil, fmt.Errorf("encode audit checkpoint sequence: %w", err)
	}
	encoded.Write(statement.ChainHash[:])
	if err := writeCheckpointString(encoded, algorithm); err != nil {
		return nil, err
	}
	if err := writeCheckpointString(encoded, statement.KeyID); err != nil {
		return nil, err
	}
	if err := binary.Write(encoded, binary.BigEndian, statement.SignedAt.UTC().UnixNano()); err != nil {
		return nil, fmt.Errorf("encode audit checkpoint signed_at: %w", err)
	}
	return encoded.Bytes(), nil
}

func validateCheckpointStatement(statement CheckpointStatement) error {
	if !statement.TenantID.Valid || !statement.CheckpointID.Valid || statement.ChainSequence <= 0 {
		return ErrInvalidCheckpoint
	}
	if allZero32(statement.ChainHash) {
		return ErrInvalidCheckpoint
	}
	if statement.Algorithm != CheckpointAlgorithmECDSAP256SHA256 {
		return ErrInvalidCheckpoint
	}
	if !validCheckpointKeyID(statement.KeyID) || statement.SignedAt.IsZero() {
		return ErrInvalidCheckpoint
	}
	return nil
}

func validateStoredCheckpoint(stored StoredCheckpoint) error {
	statement := CheckpointStatement{
		TenantID:      stored.TenantID,
		CheckpointID:  stored.ID,
		ChainSequence: stored.ChainSequence,
		ChainHash:     stored.ChainHash,
		Algorithm:     stored.Algorithm,
		KeyID:         stored.KeyID,
		SignedAt:      stored.SignedAt,
	}
	if err := validateCheckpointStatement(statement); err != nil {
		return err
	}
	if allZero32(stored.StatementDigest) || len(stored.Signature) < minCheckpointSignatureSize || len(stored.Signature) > maxCheckpointSignatureSize {
		return ErrInvalidCheckpoint
	}
	return nil
}

func validCheckpointPublicKey(publicKey *ecdsa.PublicKey) bool {
	if publicKey == nil || publicKey.Curve != elliptic.P256() || publicKey.X == nil || publicKey.Y == nil {
		return false
	}
	return elliptic.P256().IsOnCurve(publicKey.X, publicKey.Y)
}

func validCheckpointKeyID(keyID string) bool {
	if keyID == "" || !utf8.ValidString(keyID) || len(keyID) > int(^uint16(0)) {
		return false
	}
	return utf8.RuneCountInString(keyID) <= maxCheckpointKeyIDLength
}

func writeCheckpointString(destination *bytes.Buffer, value string) error {
	if len(value) > int(^uint16(0)) {
		return ErrInvalidCheckpoint
	}
	if err := binary.Write(destination, binary.BigEndian, uint16(len(value))); err != nil {
		return fmt.Errorf("encode audit checkpoint string length: %w", err)
	}
	destination.WriteString(value)
	return nil
}

func allZero32(value [sha256.Size]byte) bool {
	var zero [sha256.Size]byte
	return subtle.ConstantTimeCompare(value[:], zero[:]) == 1
}
