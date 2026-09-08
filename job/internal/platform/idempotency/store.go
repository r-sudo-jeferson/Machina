package idempotency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var (
	ErrInvalidStoreConfig      = errors.New("invalid idempotency store configuration")
	ErrInvalidClaimRequest     = errors.New("invalid idempotency claim request")
	ErrInvalidClaimResult      = errors.New("invalid idempotency claim result")
	ErrInvalidCompletion       = errors.New("invalid idempotency completion")
	ErrInvalidCompletionResult = errors.New("invalid idempotency completion result")
)

type State string

const (
	StateClaimed    State = "claimed"
	StateReplay     State = "replay"
	StateInProgress State = "in_progress"
	StateConflict   State = "conflict"
)

type ClaimRequest struct {
	Key           string
	Operation     string
	RequestHash   string
	CorrelationID pgtype.UUID
	ExpiresAt     time.Time
}

type ClaimResult struct {
	State          State
	ResponseStatus int
	ResponseBody   []byte
	CorrelationID  pgtype.UUID
}

type Completion struct {
	Key            string
	Operation      string
	RequestHash    string
	ResponseStatus int
	ResponseBody   []byte
}

type queries interface {
	ClaimIdempotencyKey(context.Context, sqlcgen.ClaimIdempotencyKeyParams) (sqlcgen.ClaimIdempotencyKeyRow, error)
	CompleteIdempotencyKey(context.Context, sqlcgen.CompleteIdempotencyKeyParams) (bool, error)
}

type Store struct {
	queries queries
}

func NewStore(q queries) (*Store, error) {
	if q == nil {
		return nil, ErrInvalidStoreConfig
	}
	return &Store{queries: q}, nil
}

func (s *Store) Claim(ctx context.Context, request ClaimRequest) (ClaimResult, error) {
	if err := validateClaimRequest(request); err != nil {
		return ClaimResult{}, err
	}

	row, err := s.queries.ClaimIdempotencyKey(ctx, sqlcgen.ClaimIdempotencyKeyParams{
		IdempotencyKey: request.Key,
		Operation:      request.Operation,
		RequestHash:    request.RequestHash,
		CorrelationID:  request.CorrelationID,
		ExpiresAt: pgtype.Timestamptz{
			Time:  request.ExpiresAt.UTC(),
			Valid: true,
		},
	})
	if err != nil {
		return ClaimResult{}, fmt.Errorf("claim idempotency key: %w", err)
	}

	result, err := mapClaimResult(row, request.CorrelationID)
	if err != nil {
		return ClaimResult{}, err
	}
	return result, nil
}

func (s *Store) Complete(ctx context.Context, completion Completion) error {
	if err := validateCompletion(completion); err != nil {
		return err
	}

	completed, err := s.queries.CompleteIdempotencyKey(ctx, sqlcgen.CompleteIdempotencyKeyParams{
		IdempotencyKey: completion.Key,
		Operation:      completion.Operation,
		RequestHash:    completion.RequestHash,
		ResponseStatus: int32(completion.ResponseStatus),
		ResponseBody:   append([]byte(nil), completion.ResponseBody...),
	})
	if err != nil {
		return fmt.Errorf("complete idempotency key: %w", err)
	}
	if !completed {
		return ErrInvalidCompletionResult
	}
	return nil
}

func validateClaimRequest(request ClaimRequest) error {
	if !validTextLength(request.Key, 16, 128) ||
		!validTextLength(request.Operation, 1, 160) ||
		!validRequestHash(request.RequestHash) ||
		!request.CorrelationID.Valid ||
		request.ExpiresAt.IsZero() {
		return ErrInvalidClaimRequest
	}
	return nil
}

func validateCompletion(completion Completion) error {
	if !validTextLength(completion.Key, 16, 128) ||
		!validTextLength(completion.Operation, 1, 160) ||
		!validRequestHash(completion.RequestHash) ||
		completion.ResponseStatus < 100 || completion.ResponseStatus > 599 ||
		!json.Valid(completion.ResponseBody) {
		return ErrInvalidCompletion
	}
	return nil
}

func mapClaimResult(row sqlcgen.ClaimIdempotencyKeyRow, requestedCorrelation pgtype.UUID) (ClaimResult, error) {
	if !row.CorrelationID.Valid {
		return ClaimResult{}, ErrInvalidClaimResult
	}

	result := ClaimResult{
		State:          State(row.ClaimState),
		ResponseStatus: int(row.ResponseStatus),
		CorrelationID:  row.CorrelationID,
	}

	switch result.State {
	case StateClaimed:
		if row.ResponseStatus != 0 || len(row.ResponseBody) != 0 || row.CorrelationID != requestedCorrelation {
			return ClaimResult{}, ErrInvalidClaimResult
		}
	case StateInProgress, StateConflict:
		if row.ResponseStatus != 0 || len(row.ResponseBody) != 0 {
			return ClaimResult{}, ErrInvalidClaimResult
		}
	case StateReplay:
		if row.ResponseStatus < 100 || row.ResponseStatus > 599 || !json.Valid(row.ResponseBody) {
			return ClaimResult{}, ErrInvalidClaimResult
		}
		result.ResponseBody = append([]byte(nil), row.ResponseBody...)
	default:
		return ClaimResult{}, ErrInvalidClaimResult
	}

	return result, nil
}

func validTextLength(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}

func validRequestHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
