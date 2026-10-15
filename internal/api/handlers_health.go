package api

import "net/http"

type healthResponse struct {
	Status string `json:"status"`
}

// handleHealth responde se o servidor está no ar. Na Fatia 2 passa a
// informar também se o cofre está selado ("sealed").
func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}
