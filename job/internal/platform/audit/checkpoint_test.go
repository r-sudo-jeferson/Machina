package audit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestDigestCheckpointStatementUsesVersionedCanonicalEncoding(t *testing.T) {
	statement := validCheckpointStatement()
	got, err := DigestCheckpointStatement(statement)
	if err != nil {
		t.Fatalf("DigestCheckpointStatement() error = %v", err)
	}

	encoded := expectedCheckpointStatementEncoding(t, statement)
	want := sha256.Sum256(encoded)
	if got != want {
		t.Fatalf("checkpoint digest = %x, want %x", got, want)
	}

	repeat, err := DigestCheckpointStatement(statement)
	if err != nil {
		t.Fatalf("DigestCheckpointStatement(repeat) error = %v", err)
	}
	if repeat != got {
		t.Fatalf("checkpoint digest is not deterministic: first=%x repeat=%x", got, repeat)
	}

	offset := statement
	offset.SignedAt = statement.SignedAt.In(time.FixedZone("offset", -3*60*60))
	offsetDigest, err := DigestCheckpointStatement(offset)
	if err != nil {
		t.Fatalf("DigestCheckpointStatement(offset) error = %v", err)
	}
	if offsetDigest != got {
		t.Fatalf("equivalent instant changed digest: utc=%x offset=%x", got, offsetDigest)
	}
}

func TestDigestCheckpointStatementFailsClosed(t *testing.T) {
	valid := validCheckpointStatement()
	cases := []struct {
		name   string
		mutate func(CheckpointStatement) CheckpointStatement
	}{
		{name: "invalid tenant", mutate: func(v CheckpointStatement) CheckpointStatement { v.TenantID = pgtype.UUID{}; return v }},
		{name: "invalid checkpoint id", mutate: func(v CheckpointStatement) CheckpointStatement { v.CheckpointID = pgtype.UUID{}; return v }},
		{name: "zero sequence", mutate: func(v CheckpointStatement) CheckpointStatement { v.ChainSequence = 0; return v }},
		{name: "negative sequence", mutate: func(v CheckpointStatement) CheckpointStatement { v.ChainSequence = -1; return v }},
		{name: "zero chain hash", mutate: func(v CheckpointStatement) CheckpointStatement { v.ChainHash = [32]byte{}; return v }},
		{name: "unknown algorithm", mutate: func(v CheckpointStatement) CheckpointStatement { v.Algorithm = CheckpointAlgorithm("rsa-sha256"); return v }},
		{name: "empty key id", mutate: func(v CheckpointStatement) CheckpointStatement { v.KeyID = ""; return v }},
		{name: "oversized key id", mutate: func(v CheckpointStatement) CheckpointStatement { v.KeyID = strings.Repeat("k", 201); return v }},
		{name: "invalid utf8 key id", mutate: func(v CheckpointStatement) CheckpointStatement { v.KeyID = string([]byte{0xff, 0xfe}); return v }},
		{name: "zero signed at", mutate: func(v CheckpointStatement) CheckpointStatement { v.SignedAt = time.Time{}; return v }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DigestCheckpointStatement(tc.mutate(valid)); !errors.Is(err, ErrInvalidCheckpoint) {
				t.Fatalf("DigestCheckpointStatement() error = %v, want ErrInvalidCheckpoint", err)
			}
		})
	}
}

func TestVerifyCheckpointSignatureDetectsCommittedFieldTampering(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	stored := signedStoredCheckpoint(t, privateKey, validCheckpointStatement())
	if err := VerifyCheckpointSignature(&privateKey.PublicKey, stored); err != nil {
		t.Fatalf("VerifyCheckpointSignature(valid) error = %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(StoredCheckpoint) StoredCheckpoint
	}{
		{name: "tenant", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.TenantID = auditTestUUID(0x31); return v }},
		{name: "checkpoint id", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.ID = auditTestUUID(0x32); return v }},
		{name: "sequence", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.ChainSequence++; return v }},
		{name: "chain hash", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.ChainHash[0] ^= 0xff; return v }},
		{name: "digest", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.StatementDigest[0] ^= 0xff; return v }},
		{name: "algorithm", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.Algorithm = CheckpointAlgorithm("rsa-sha256"); return v }},
		{name: "key id", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.KeyID = "other-key"; return v }},
		{name: "signature", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.Signature = append([]byte(nil), v.Signature...); v.Signature[len(v.Signature)-1] ^= 0xff; return v }},
		{name: "signed at", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.SignedAt = v.SignedAt.Add(time.Nanosecond); return v }},
	}

	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyCheckpointSignature(&privateKey.PublicKey, tc.mutate(stored)); !errors.Is(err, ErrInvalidCheckpointSignature) && !errors.Is(err, ErrInvalidCheckpoint) {
				t.Fatalf("VerifyCheckpointSignature() error = %v, want fail-closed checkpoint error", err)
			}
		})
	}
}

func TestVerifyCheckpointSignatureRejectsUntrustedKeyShape(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P256) error = %v", err)
	}
	stored := signedStoredCheckpoint(t, privateKey, validCheckpointStatement())

	if err := VerifyCheckpointSignature(nil, stored); !errors.Is(err, ErrInvalidCheckpointSignature) {
		t.Fatalf("VerifyCheckpointSignature(nil) error = %v, want ErrInvalidCheckpointSignature", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P384) error = %v", err)
	}
	if err := VerifyCheckpointSignature(&p384.PublicKey, stored); !errors.Is(err, ErrInvalidCheckpointSignature) {
		t.Fatalf("VerifyCheckpointSignature(P384) error = %v, want ErrInvalidCheckpointSignature", err)
	}
}

func validCheckpointStatement() CheckpointStatement {
	var chainHash [32]byte
	for i := range chainHash {
		chainHash[i] = byte(i + 1)
	}
	return CheckpointStatement{
		TenantID:       auditTestUUID(0x11),
		CheckpointID:   auditTestUUID(0x22),
		ChainSequence:  7,
		ChainHash:      chainHash,
		Algorithm:      CheckpointAlgorithmECDSAP256SHA256,
		KeyID:          "kms/test-key/v1",
		SignedAt:       time.Date(2026, 9, 9, 11, 40, 0, 123456789, time.UTC),
	}
}

func signedStoredCheckpoint(t *testing.T, privateKey *ecdsa.PrivateKey, statement CheckpointStatement) StoredCheckpoint {
	t.Helper()
	digest, err := DigestCheckpointStatement(statement)
	if err != nil {
		t.Fatalf("DigestCheckpointStatement() error = %v", err)
	}
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1() error = %v", err)
	}
	return StoredCheckpoint{
		TenantID:        statement.TenantID,
		ID:              statement.CheckpointID,
		ChainSequence:   statement.ChainSequence,
		ChainHash:       statement.ChainHash,
		StatementDigest: digest,
		Algorithm:       statement.Algorithm,
		KeyID:           statement.KeyID,
		Signature:       append([]byte(nil), signature...),
		SignedAt:        statement.SignedAt,
	}
}

func expectedCheckpointStatementEncoding(t *testing.T, statement CheckpointStatement) []byte {
	t.Helper()
	if !utf8.ValidString(statement.KeyID) {
		t.Fatal("test fixture key id must be valid UTF-8")
	}
	var encoded bytes.Buffer
	encoded.WriteString("MCH-AUDIT-CHECKPOINT")
	encoded.WriteByte(0)
	encoded.WriteByte(1)
	encoded.Write(statement.TenantID.Bytes[:])
	encoded.Write(statement.CheckpointID.Bytes[:])
	if err := binary.Write(&encoded, binary.BigEndian, uint64(statement.ChainSequence)); err != nil {
		t.Fatalf("encode sequence: %v", err)
	}
	encoded.Write(statement.ChainHash[:])
	writeCheckpointTestString(t, &encoded, string(statement.Algorithm))
	writeCheckpointTestString(t, &encoded, statement.KeyID)
	if err := binary.Write(&encoded, binary.BigEndian, statement.SignedAt.UTC().UnixNano()); err != nil {
		t.Fatalf("encode signed at: %v", err)
	}
	return encoded.Bytes()
}

func writeCheckpointTestString(t *testing.T, destination *bytes.Buffer, value string) {
	t.Helper()
	if len(value) > int(^uint16(0)) {
		t.Fatalf("test fixture string too long: %d", len(value))
	}
	if err := binary.Write(destination, binary.BigEndian, uint16(len(value))); err != nil {
		t.Fatalf("encode string length: %v", err)
	}
	destination.WriteString(value)
}

func TestStoredCheckpointDoesNotAliasSignatureInput(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	stored := signedStoredCheckpoint(t, privateKey, validCheckpointStatement())
	copyOfSignature := append([]byte(nil), stored.Signature...)
	if !reflect.DeepEqual(copyOfSignature, stored.Signature) {
		t.Fatal("signature fixture copy differs before mutation")
	}
	copyOfSignature[0] ^= 0xff
	if reflect.DeepEqual(copyOfSignature, stored.Signature) {
		t.Fatal("signature fixture unexpectedly aliases copied bytes")
	}
}
