package api

import "net/http"

type healthResponse struct {
	Status string `json:"status"`
	Sealed bool   `json:"sealed"`
}

// handleHealth responde se o servidor está no ar e se o cofre está selado.
func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok", Sealed: s.vault.Sealed()})
}
