package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/httpx"
)

const (
	tenantSwitchPath       = "/v1/tenant-switch"
	defaultTenantSwitchMax = 4 << 10
)

type tenantSwitchExecutor interface {
	Switch(context.Context, TenantSwitchRequest) (TenantSwitchResult, error)
}

type TenantSwitchHTTPHandler struct {
	switcher     tenantSwitchExecutor
	maxBodyBytes int64
}

func NewTenantSwitchHTTPHandler(switcher tenantSwitchExecutor) (*TenantSwitchHTTPHandler, error) {
	if switcher == nil {
		return nil, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return &TenantSwitchHTTPHandler{switcher: switcher, maxBodyBytes: defaultTenantSwitchMax}, nil
}

func (h *TenantSwitchHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.switcher == nil {
		writeTenantSwitchProblem(w, http.StatusServiceUnavailable, "tenant_switch_unavailable", pgtype.UUID{})
		return
	}
	if r == nil || r.URL == nil || r.URL.Path != tenantSwitchPath {
		writeTenantSwitchProblem(w, http.StatusNotFound, "route_not_found", pgtype.UUID{})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeTenantSwitchProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", pgtype.UUID{})
		return
	}

	session, ok := SessionFromContext(r.Context())
	if !ok || !session.ID.Valid {
		writeTenantSwitchProblem(w, http.StatusUnauthorized, "session_required", pgtype.UUID{})
		return
	}
	presentedToken, ok := singleCookieValue(r, SessionCookieName)
	if !ok || presentedToken == "" {
		writeTenantSwitchProblem(w, http.StatusUnauthorized, "session_required", pgtype.UUID{})
		return
	}
	if !validTenantSwitchCSRF(r, session) {
		writeTenantSwitchProblem(w, http.StatusForbidden, "csrf_invalid", pgtype.UUID{})
		return
	}

	idempotencyValues := r.Header.Values("Idempotency-Key")
	if len(idempotencyValues) != 1 || !validTenantSwitchKey(idempotencyValues[0]) {
		writeTenantSwitchProblem(w, http.StatusBadRequest, "idempotency_key_invalid", pgtype.UUID{})
		return
	}
	targetTenant, ok := decodeTenantSwitchHTTPBody(w, r, h.maxBodyBytes)
	if !ok {
		return
	}

	correlationID, err := newTenantSwitchUUID()
	if err != nil {
		writeTenantSwitchProblem(w, http.StatusServiceUnavailable, "correlation_unavailable", pgtype.UUID{})
		return
	}
	result, err := h.switcher.Switch(r.Context(), TenantSwitchRequest{
		PresentedSessionToken: presentedToken,
		TargetTenantID:        targetTenant,
		IdempotencyKey:        idempotencyValues[0],
		CorrelationID:         correlationID,
	})
	if err != nil {
		status, code := mapTenantSwitchHTTPError(err)
		writeTenantSwitchProblem(w, status, code, correlationID)
		return
	}
	if err := validateTenantSwitchHTTPResult(result); err != nil {
		writeTenantSwitchProblem(w, http.StatusServiceUnavailable, "tenant_switch_result_invalid", correlationID)
		return
	}

	httpx.NoStore(w)
	w.Header().Set("Content-Type", "application/json")
	httpx.StrongETag(w, result.ETag)
	if !result.Replay {
		http.SetCookie(w, SessionCookie(result.SessionToken, result.SessionExpiresAt))
		http.SetCookie(w, CSRFCookie(result.CSRFToken, result.SessionExpiresAt))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result.ResponseBody)
}

type tenantSwitchHTTPBody struct {
	TenantID string `json:"tenant_id"`
}

func decodeTenantSwitchHTTPBody(w http.ResponseWriter, r *http.Request, maxBodyBytes int64) (pgtype.UUID, bool) {
	if r == nil || r.Body == nil {
		writeTenantSwitchProblem(w, http.StatusBadRequest, "request_body_invalid", pgtype.UUID{})
		return pgtype.UUID{}, false
	}
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultTenantSwitchMax
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var body tenantSwitchHTTPBody
	if err := decoder.Decode(&body); err != nil {
		writeTenantSwitchProblem(w, http.StatusBadRequest, "request_body_invalid", pgtype.UUID{})
		return pgtype.UUID{}, false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeTenantSwitchProblem(w, http.StatusBadRequest, "request_body_invalid", pgtype.UUID{})
		return pgtype.UUID{}, false
	}
	if strings.TrimSpace(body.TenantID) != body.TenantID {
		writeTenantSwitchProblem(w, http.StatusBadRequest, "tenant_id_invalid", pgtype.UUID{})
		return pgtype.UUID{}, false
	}
	target, ok := parseUUIDText(body.TenantID)
	if !ok {
		writeTenantSwitchProblem(w, http.StatusBadRequest, "tenant_id_invalid", pgtype.UUID{})
		return pgtype.UUID{}, false
	}
	return target, true
}

func validTenantSwitchCSRF(r *http.Request, session sqlcgen.GetActiveSessionRow) bool {
	if r == nil {
		return false
	}
	headerValues := r.Header.Values(CSRFHeaderName)
	cookieValue, cookieOK := singleCookieValue(r, CSRFCookieName)
	return len(headerValues) == 1 && headerValues[0] != "" && cookieOK && cookieValue != "" &&
		VerifyCSRF(headerValues[0], cookieValue, session.CsrfTokenHash)
}

func validateTenantSwitchHTTPResult(result TenantSwitchResult) error {
	if result.ResponseStatus != http.StatusOK || len(result.ResponseBody) == 0 ||
		!json.Valid(result.ResponseBody) || result.ETag == "" ||
		result.ETag != strongTenantSwitchETag(result.ResponseBody) ||
		!result.CorrelationID.Valid || result.SessionExpiresAt.IsZero() {
		return ErrInvalidTenantSwitchOutcome
	}
	if result.Replay {
		if result.SessionToken != "" || result.CSRFToken != "" {
			return ErrInvalidTenantSwitchOutcome
		}
		return nil
	}
	if result.SessionToken == "" || result.CSRFToken == "" || result.SessionToken == result.CSRFToken {
		return ErrInvalidTenantSwitchOutcome
	}
	return nil
}

func mapTenantSwitchHTTPError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrInvalidTenantSwitchRequest), errors.Is(err, ErrInvalidTenantSwitchScope),
		errors.Is(err, ErrInvalidTenantSwitchOutcome), errors.Is(err, ErrInvalidTenantSwitchPair):
		return http.StatusBadRequest, "tenant_switch_invalid"
	case errors.Is(err, ErrTenantSwitchScopeConflict):
		return http.StatusConflict, "idempotency_conflict"
	case errors.Is(err, ErrTenantSwitchInProgress):
		return http.StatusConflict, "idempotency_in_progress"
	case errors.Is(err, ErrTenantSwitchStale):
		return http.StatusConflict, "tenant_switch_stale"
	case errors.Is(err, ErrUncertainTenantSwitchCommit):
		return http.StatusServiceUnavailable, "reauthentication_required"
	default:
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "42501" {
			return http.StatusUnauthorized, "session_invalid"
		}
		return http.StatusServiceUnavailable, "tenant_switch_unavailable"
	}
}

func writeTenantSwitchProblem(w http.ResponseWriter, status int, code string, correlationID pgtype.UUID) {
	problem := httpx.Problem{Type: "about:blank", Title: http.StatusText(status), Status: status, Code: code}
	if correlationID.Valid {
		problem.CorrelationID = uuidText(correlationID)
	}
	httpx.WriteProblem(w, problem)
}
