package api

import "net/http"

type secretItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type listSecretsResponse struct {
	Project string       `json:"project"`
	Secrets []secretItem `json:"secrets"`
}

// fixedSecrets faz o papel do cofre na Fatia 1: um segredo fixo no projeto
// "demo", só para provar a injeção de ponta a ponta. A Fatia 2 troca isto
// pelo PostgreSQL com envelope encryption.
var fixedSecrets = map[string][]secretItem{
	"demo": {{Key: "DB_PASSWORD", Value: "senha-fixa-da-fatia-1"}},
}

// handleListSecrets devolve todos os segredos atuais do projeto, com valor.
// É a rota usada pelo "envmem run".
func handleListSecrets(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	secrets, ok := fixedSecrets[project]
	if !ok {
		writeError(w, http.StatusNotFound, "project_not_found", "projeto não encontrado")
		return
	}
	writeJSON(w, http.StatusOK, listSecretsResponse{Project: project, Secrets: secrets})
}
