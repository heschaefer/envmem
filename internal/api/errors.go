package api

import (
	"encoding/json"
	"net/http"
)

// errorBody é o formato de todo erro da API: {"error": "codigo", "message": "texto"}.
// A mensagem nunca deve conter segredos nem tokens.
type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// writeJSON serializa v como resposta JSON com o status dado.
func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	// Respostas podem conter segredos: nenhum cache (navegador, proxy) deve
	// guardar uma cópia delas.
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// Depois do WriteHeader não há como mudar o status; se a escrita falhar,
	// o cliente percebe pela conexão interrompida.
	_ = json.NewEncoder(w).Encode(v)
}

// writeError responde com o formato de erro padrão da API.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: code, Message: message})
}
