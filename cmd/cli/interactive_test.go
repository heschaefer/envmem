package main

import (
	"slices"
	"testing"
)

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
	manage := []menuAction{actShowValue, actSetSecret, actTrashSecret, actTrash, actMembers}
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
		if isAdmin(tt.role) != tt.purge {
			t.Errorf("%s: isAdmin = %v, quero %v", tt.role, isAdmin(tt.role), tt.purge)
		}
	}
}

// O gestor só mexe com desenvolvedores; admin e superadmin, com todos.
func TestMemberActions(t *testing.T) {
	tests := []struct {
		viewer, member string
		want           []menuAction
	}{
		{"gestor", "desenvolvedor", []menuAction{actRemoveMember, actBack}},
		{"gestor", "gestor", []menuAction{actBack}},
		{"admin", "desenvolvedor", []menuAction{actMakeGestor, actRemoveMember, actBack}},
		{"admin", "gestor", []menuAction{actMakeDev, actRemoveMember, actBack}},
		{"superadmin", "gestor", []menuAction{actMakeDev, actRemoveMember, actBack}},
		{"desenvolvedor", "desenvolvedor", []menuAction{actBack}},
	}
	for _, tt := range tests {
		if got := actionsOf(memberActions(tt.viewer, tt.member)); !slices.Equal(got, tt.want) {
			t.Errorf("memberActions(%s, %s) = %v, quero %v", tt.viewer, tt.member, got, tt.want)
		}
	}
}

// Projetos para admin e superadmin; usuários só para o superadmin; "Sair"
// sempre por último.
func TestGlobalActions(t *testing.T) {
	tests := []struct {
		role string
		want []menuAction
	}{
		{"", []menuAction{actQuit}},
		{"admin", []menuAction{actCreateProject, actDeleteProject, actQuit}},
		{"superadmin", []menuAction{actCreateProject, actDeleteProject, actUsers, actQuit}},
	}
	for _, tt := range tests {
		if got := actionsOf(globalActions(tt.role)); !slices.Equal(got, tt.want) {
			t.Errorf("globalActions(%q) = %v, quero %v", tt.role, got, tt.want)
		}
	}
}

func actionsOf(items []actionItem) []menuAction {
	out := make([]menuAction, len(items))
	for i, it := range items {
		out[i] = it.action
	}
	return out
}
