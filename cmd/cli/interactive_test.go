package main

import "testing"

// Todo papel vê as ações do desenvolvedor (rodar um comando e ver os
// nomes) e o "Voltar", que fica por último.
func TestProjectActions(t *testing.T) {
	for _, role := range []string{"desenvolvedor", "gestor", "admin", "superadmin"} {
		items := projectActions(role)
		if !hasAction(items, actListNames) || !hasAction(items, actRun) {
			t.Errorf("%s: faltam as ações do desenvolvedor", role)
		}
		if last := items[len(items)-1]; last.action != actBack {
			t.Errorf("%s: a última opção é %q, quero Voltar", role, last.label)
		}
	}
}

func hasAction(items []actionItem, a menuAction) bool {
	for _, it := range items {
		if it.action == a {
			return true
		}
	}
	return false
}

// O menu de cada papel segue a tabela de permissões do CLAUDE.md. É só o
// que aparece: o servidor confere cada ação de novo.
func TestProjectActionsByRole(t *testing.T) {
	manage := []menuAction{actShowValue, actSetSecret, actTrashSecret, actTrash}
	tests := []struct {
		role          string
		manage, purge bool
	}{
		{"desenvolvedor", false, false},
		{"gestor", true, false},
		{"admin", true, true},
		{"superadmin", true, true},
		// Um papel desconhecido (servidor mais novo, resposta estranha) não
		// ganha nada além do básico.
		{"outro", false, false},
	}
	for _, tt := range tests {
		items := projectActions(tt.role)
		for _, a := range manage {
			if hasAction(items, a) != tt.manage {
				t.Errorf("%s: ação %d presente = %v, quero %v", tt.role, a, hasAction(items, a), tt.manage)
			}
		}
		if canPurge(tt.role) != tt.purge {
			t.Errorf("%s: canPurge = %v, quero %v", tt.role, canPurge(tt.role), tt.purge)
		}
	}
}
