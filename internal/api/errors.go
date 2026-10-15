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

// maxBodyBytes limita o corpo das requisições, para que um cliente não
// esgote a memória do servidor com um corpo enorme.
const maxBodyBytes = 64 << 10 // 64 KiB

// decodeJSON lê o corpo da requisição em v. O erro não é repassado ao
// cliente nem ao log como está, porque pode citar trechos do corpo (que pode
// conter a chave-mestra ou um segredo).
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// writeError responde com o formato de erro padrão da API.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: code, Message: message})
}
