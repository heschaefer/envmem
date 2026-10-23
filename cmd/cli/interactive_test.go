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
