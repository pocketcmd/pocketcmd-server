// Package httperr implements the API JSON wire format for responses.
package httperr

import (
	"encoding/json"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func JSON(w http.ResponseWriter, status int, code string) {
	_ = WriteJSON(w, status, map[string]string{"error": code})
}
