package httpx

import (
	"encoding/json"
	"net/http"
)

type Problem struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Detail        string `json:"detail,omitempty"`
	Instance      string `json:"instance,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	Code          string `json:"code,omitempty"`
}

func NoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

func StrongETag(w http.ResponseWriter, value string) {
	if value != "" {
		w.Header().Set("ETag", value)
	}
}

func WriteProblem(w http.ResponseWriter, problem Problem) {
	if problem.Status < 400 || problem.Status > 599 {
		problem.Status = http.StatusInternalServerError
	}
	NoStore(w)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(problem.Status)
	_ = json.NewEncoder(w).Encode(problem)
}
