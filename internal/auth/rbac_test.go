package auth

import "testing"

// A tabela de papéis do CLAUDE.md, linha por linha. Mudar uma permissão
// sem mudar a tabela (ou o contrário) quebra este teste.
func TestPermissionMatrix(t *testing.T) {
	const (
		S = RoleSuperadmin
		A = RoleAdmin
		G = RoleGestor
		D = RoleDesenvolvedor
		U = RoleUser
	)
	tests := []struct {
		row     string
		perm    Permission
		allowed []Role
	}{
		{"Criar e remover usuários e admins; resetar senha", PermManageUsers, []Role{S}},
		{"Seal do cofre", PermSeal, []Role{S}},
		{"Ver auditoria", PermReadAudit, []Role{S, A}},
		{"Criar e excluir projetos", PermManageProjects, []Role{S, A}},
		{"Nomear gestores", PermNominateManagers, []Role{S, A}},
		{"Adicionar e remover desenvolvedores", PermManageMembers, []Role{S, A, G}},
		{"Criar, alterar, remover e restaurar variáveis", PermWriteSecrets, []Role{S, A, G}},
		{"Excluir variáveis definitivamente", PermPurgeSecrets, []Role{S, A}},
		{"Ver valores das variáveis", PermReadSecretValue, []Role{S, A, G}},
		{"Listar nomes das variáveis", PermListSecretNames, []Role{S, A, G, D}},
		{"Usar no run", PermUseSecrets, []Role{S, A, G, D}},
		{"Sessão (me, senha, listar os próprios projetos)", PermSession, []Role{S, A, U}},
	}
	all := []Role{S, A, G, D, U}
	for _, tt := range tests {
		want := map[Role]bool{}
		for _, r := range tt.allowed {
			want[r] = true
		}
		for _, r := range all {
			if got := tt.perm.Allows(r); got != want[r] {
				t.Errorf("%s: Allows(%s) = %v, quero %v", tt.row, r, got, want[r])
			}
		}
	}
}

func TestProjectRole(t *testing.T) {
	tests := []struct {
		global, member string
		want           Role
		ok             bool
	}{
		{"superadmin", "", RoleSuperadmin, true},
		{"admin", "desenvolvedor", RoleAdmin, true}, // o papel global prevalece
		{"", "gestor", RoleGestor, true},
		{"", "desenvolvedor", RoleDesenvolvedor, true},
		{"", "", "", false},      // não é membro: projeto "não existe" para ele
		{"", "outro", "", false}, // papel desconhecido no banco não vale nada
	}
	for _, tt := range tests {
		got, ok := ProjectRole(tt.global, tt.member)
		if got != tt.want || ok != tt.ok {
			t.Errorf("ProjectRole(%q, %q) = %q, %v; quero %q, %v", tt.global, tt.member, got, ok, tt.want, tt.ok)
		}
	}
	if GlobalRole("") != RoleUser || GlobalRole("qualquer") != RoleUser {
		t.Error("sem papel global deveria ser RoleUser")
	}
}
