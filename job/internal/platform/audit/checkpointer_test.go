package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestCheckpointerCreatesVerifiedCheckpointOutsideStoreCalls(t *testing.T) {
	privateKey := mustCheckpointKey(t)
	state := &checkpointerTestState{}
	store := &recordingCheckpointStore{
		state: state,
		head:  validChainHead(),
	}
	signer := &recordingCheckpointSigner{
		state:      state,
		privateKey: privateKey,
		keyID:      "kms/test-key/v1",
	}
	checkpointID := auditTestUUID(0x66)
	checkpointer, err := NewCheckpointer(
		store,
		signer,
		func() time.Time { return time.Date(2026, 9, 9, 12, 0, 0, 123, time.FixedZone("offset", -3*60*60)) },
		func() (pgtype.UUID, error) { return checkpointID, nil },
	)
	if err != nil {
		t.Fatalf("NewCheckpointer() error = %v", err)
	}

	result, err := checkpointer.Checkpoint(context.Background(), validChainHead().TenantID)
	if err != nil {
		t.Fatalf("Checkpoint() error = %v", err)
	}
	if result.Replay {
		t.Fatal("new checkpoint unexpectedly reported replay")
	}
	if result.Checkpoint.ID != checkpointID || result.Checkpoint.SignedAt.Location() != time.UTC {
		t.Fatalf("CheckpointResult = %#v", result)
	}
	if err := VerifyCheckpointSignature(&privateKey.PublicKey, result.Checkpoint); err != nil {
		t.Fatalf("VerifyCheckpointSignature(result) error = %v", err)
	}
	wantCalls := []string{"Head", "Find", "SignSHA256", "PublicKey", "Insert"}
	if !reflect.DeepEqual(state.calls, wantCalls) {
		t.Fatalf("call order = %#v, want %#v", state.calls, wantCalls)
	}
	if state.signerObservedStoreActive {
		t.Fatal("signer was invoked while a store operation was active")
	}
}

func TestCheckpointerSignerFailuresDoNotPersist(t *testing.T) {
	privateKey := mustCheckpointKey(t)
	tenantID := validChainHead().TenantID

	cases := []struct {
		name      string
		signErr   error
		publicErr error
	}{
		{name: "signing outage", signErr: errors.New("kms sign unavailable")},
		{name: "public key outage", publicErr: errors.New("kms public key unavailable")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := &checkpointerTestState{}
			store := &recordingCheckpointStore{state: state, head: validChainHead()}
			signer := &recordingCheckpointSigner{
				state:      state,
				privateKey: privateKey,
				keyID:      "kms/test-key/v1",
				signErr:    tc.signErr,
				publicErr:  tc.publicErr,
			}
			checkpointer := mustCheckpointer(t, store, signer)
			_, err := checkpointer.Checkpoint(context.Background(), tenantID)
			injected := tc.signErr
			if injected == nil {
				injected = tc.publicErr
			}
			if !errors.Is(err, injected) {
				t.Fatalf("Checkpoint() error = %v, want injected %v", err, injected)
			}
			if store.insertCalls != 0 {
				t.Fatalf("Insert calls = %d, want 0", store.insertCalls)
			}
			if state.signerObservedStoreActive {
				t.Fatal("signer was invoked while a store operation was active")
			}

			signer.signErr = nil
			signer.publicErr = nil
			state.calls = nil
			result, retryErr := checkpointer.Checkpoint(context.Background(), tenantID)
			if retryErr != nil {
				t.Fatalf("Checkpoint(retry) error = %v", retryErr)
			}
			if result.Replay || store.insertCalls != 1 {
				t.Fatalf("retry result=%#v insertCalls=%d", result, store.insertCalls)
			}
		})
	}
}

func TestCheckpointerReplaysOnlyVerifiedExistingCheckpoint(t *testing.T) {
	privateKey := mustCheckpointKey(t)
	head := validChainHead()
	existing := signedCheckpointForHead(t, privateKey, head, auditTestUUID(0x70), "kms/test-key/v1")

	state := &checkpointerTestState{}
	store := &recordingCheckpointStore{state: state, head: head, existing: &existing}
	signer := &recordingCheckpointSigner{state: state, privateKey: privateKey, keyID: existing.KeyID}
	checkpointer := mustCheckpointer(t, store, signer)

	result, err := checkpointer.Checkpoint(context.Background(), head.TenantID)
	if err != nil {
		t.Fatalf("Checkpoint(replay) error = %v", err)
	}
	if !result.Replay || result.Checkpoint.ID != existing.ID {
		t.Fatalf("CheckpointResult = %#v, want verified replay", result)
	}
	if signer.signCalls != 0 || store.insertCalls != 0 || signer.publicKeyCalls != 1 {
		t.Fatalf("replay sign=%d public=%d insert=%d", signer.signCalls, signer.publicKeyCalls, store.insertCalls)
	}

	tampered := existing
	tampered.StatementDigest[0] ^= 0xff
	store.existing = &tampered
	state.calls = nil
	if _, err := checkpointer.Checkpoint(context.Background(), head.TenantID); !errors.Is(err, ErrInvalidCheckpointSignature) {
		t.Fatalf("Checkpoint(tampered replay) error = %v, want ErrInvalidCheckpointSignature", err)
	}
	if signer.signCalls != 0 || store.insertCalls != 0 {
		t.Fatalf("tampered replay sign=%d insert=%d, want zero", signer.signCalls, store.insertCalls)
	}
}

func TestCheckpointerVerifiesInsertRaceWinner(t *testing.T) {
	privateKey := mustCheckpointKey(t)
	head := validChainHead()
	winner := signedCheckpointForHead(t, privateKey, head, auditTestUUID(0x71), "kms/test-key/v1")
	state := &checkpointerTestState{}
	store := &recordingCheckpointStore{state: state, head: head, insertResult: &winner}
	signer := &recordingCheckpointSigner{state: state, privateKey: privateKey, keyID: winner.KeyID}
	checkpointer := mustCheckpointer(t, store, signer)

	result, err := checkpointer.Checkpoint(context.Background(), head.TenantID)
	if err != nil {
		t.Fatalf("Checkpoint(insert race) error = %v", err)
	}
	if !result.Replay || result.Checkpoint.ID != winner.ID {
		t.Fatalf("CheckpointResult = %#v, want verified race winner replay", result)
	}

	tampered := winner
	tampered.Signature = append([]byte(nil), winner.Signature...)
	tampered.Signature[len(tampered.Signature)-1] ^= 0xff
	store.insertResult = &tampered
	if _, err := checkpointer.Checkpoint(context.Background(), head.TenantID); !errors.Is(err, ErrInvalidCheckpointSignature) {
		t.Fatalf("Checkpoint(tampered race winner) error = %v, want ErrInvalidCheckpointSignature", err)
	}
}

func TestCheckpointerRejectsMissingHeadAndInvalidDependencies(t *testing.T) {
	privateKey := mustCheckpointKey(t)
	state := &checkpointerTestState{}
	store := &recordingCheckpointStore{state: state, headErr: ErrNoAuditEvents}
	signer := &recordingCheckpointSigner{state: state, privateKey: privateKey, keyID: "kms/test-key/v1"}
	checkpointer := mustCheckpointer(t, store, signer)
	if _, err := checkpointer.Checkpoint(context.Background(), auditTestUUID(0x11)); !errors.Is(err, ErrNoAuditEvents) {
		t.Fatalf("Checkpoint(no events) error = %v, want ErrNoAuditEvents", err)
	}
	if signer.signCalls != 0 || store.insertCalls != 0 {
		t.Fatalf("no-events sign=%d insert=%d", signer.signCalls, store.insertCalls)
	}

	if _, err := NewCheckpointer(nil, signer, time.Now, func() (pgtype.UUID, error) { return auditTestUUID(0x01), nil }); !errors.Is(err, ErrInvalidCheckpointer) {
		t.Fatalf("NewCheckpointer(nil store) error = %v, want ErrInvalidCheckpointer", err)
	}
	if _, err := NewCheckpointer(store, nil, time.Now, func() (pgtype.UUID, error) { return auditTestUUID(0x01), nil }); !errors.Is(err, ErrInvalidCheckpointer) {
		t.Fatalf("NewCheckpointer(nil signer) error = %v, want ErrInvalidCheckpointer", err)
	}
}

type checkpointerTestState struct {
	calls                     []string
	storeActive               bool
	signerObservedStoreActive bool
}

type recordingCheckpointStore struct {
	state        *checkpointerTestState
	head         ChainHead
	headErr      error
	existing     *StoredCheckpoint
	insertResult *StoredCheckpoint
	insertCalls  int
}

func (s *recordingCheckpointStore) Head(_ context.Context, _ pgtype.UUID) (ChainHead, error) {
	s.enterStore("Head")
	defer s.leaveStore()
	if s.headErr != nil {
		return ChainHead{}, s.headErr
	}
	return s.head, nil
}

func (s *recordingCheckpointStore) Find(_ context.Context, _ pgtype.UUID, _ int64, _ string) (StoredCheckpoint, error) {
	s.enterStore("Find")
	defer s.leaveStore()
	if s.existing == nil {
		return StoredCheckpoint{}, ErrCheckpointNotFound
	}
	return cloneStoredCheckpoint(*s.existing), nil
}

func (s *recordingCheckpointStore) Insert(_ context.Context, checkpoint StoredCheckpoint) (StoredCheckpoint, error) {
	s.enterStore("Insert")
	defer s.leaveStore()
	s.insertCalls++
	if s.insertResult != nil {
		return cloneStoredCheckpoint(*s.insertResult), nil
	}
	return cloneStoredCheckpoint(checkpoint), nil
}

func (s *recordingCheckpointStore) enterStore(call string) {
	if s.state.storeActive {
		panic("nested store call in checkpoint test")
	}
	s.state.storeActive = true
	s.state.calls = append(s.state.calls, call)
}

func (s *recordingCheckpointStore) leaveStore() {
	s.state.storeActive = false
}

type recordingCheckpointSigner struct {
	state          *checkpointerTestState
	privateKey     *ecdsa.PrivateKey
	keyID          string
	signErr        error
	publicErr      error
	signCalls      int
	publicKeyCalls int
}

func (s *recordingCheckpointSigner) KeyID() string { return s.keyID }

func (s *recordingCheckpointSigner) SignSHA256(_ context.Context, digest [32]byte) ([]byte, error) {
	s.state.calls = append(s.state.calls, "SignSHA256")
	s.signCalls++
	s.observeStoreState()
	if s.signErr != nil {
		return nil, s.signErr
	}
	return ecdsa.SignASN1(rand.Reader, s.privateKey, digest[:])
}

func (s *recordingCheckpointSigner) PublicKey(_ context.Context) (*ecdsa.PublicKey, error) {
	s.state.calls = append(s.state.calls, "PublicKey")
	s.publicKeyCalls++
	s.observeStoreState()
	if s.publicErr != nil {
		return nil, s.publicErr
	}
	return &s.privateKey.PublicKey, nil
}

func (s *recordingCheckpointSigner) observeStoreState() {
	if s.state.storeActive {
		s.state.signerObservedStoreActive = true
	}
}

func mustCheckpointer(t *testing.T, store CheckpointStore, signer CheckpointSigner) *Checkpointer {
	t.Helper()
	checkpointer, err := NewCheckpointer(
		store,
		signer,
		func() time.Time { return time.Date(2026, 9, 9, 15, 0, 0, 0, time.UTC) },
		func() (pgtype.UUID, error) { return auditTestUUID(0x65), nil },
	)
	if err != nil {
		t.Fatalf("NewCheckpointer() error = %v", err)
	}
	return checkpointer
}

func mustCheckpointKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	return key
}

func validChainHead() ChainHead {
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(0xa0 + i)
	}
	return ChainHead{TenantID: auditTestUUID(0x11), Sequence: 9, Hash: hash}
}

func signedCheckpointForHead(t *testing.T, key *ecdsa.PrivateKey, head ChainHead, id pgtype.UUID, keyID string) StoredCheckpoint {
	t.Helper()
	statement := CheckpointStatement{
		TenantID:      head.TenantID,
		CheckpointID:  id,
		ChainSequence: head.Sequence,
		ChainHash:     head.Hash,
		Algorithm:     CheckpointAlgorithmECDSAP256SHA256,
		KeyID:         keyID,
		SignedAt:      time.Date(2026, 9, 9, 15, 0, 0, 0, time.UTC),
	}
	return signedStoredCheckpoint(t, key, statement)
}

func cloneStoredCheckpoint(checkpoint StoredCheckpoint) StoredCheckpoint {
	checkpoint.Signature = append([]byte(nil), checkpoint.Signature...)
	return checkpoint
}
