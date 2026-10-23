package main

import "testing"

// Todo papel vê a lista de nomes e o "Voltar", que fica por último.
func TestProjectActions(t *testing.T) {
	for _, role := range []string{"desenvolvedor", "gestor", "admin", "superadmin"} {
		items := projectActions(role)
		if !hasAction(items, actListNames) {
			t.Errorf("%s: falta ver os nomes", role)
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
