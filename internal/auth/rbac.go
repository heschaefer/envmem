package auth

// Papéis e permissões (decisão 5). Esta é a tabela de papéis do CLAUDE.md
// em forma de código: cada permissão diz quais papéis a têm. Cada rota da
// API é registrada com exatamente uma permissão, e quem decide é sempre o
// servidor (esconder uma opção no CLI não é controle de acesso).

// Role é o papel de quem faz a requisição, já resolvido para o contexto da
// rota: numa rota de projeto, o papel no projeto; fora de projeto, o papel
// global.
type Role string

const (
	RoleSuperadmin    Role = "superadmin"
	RoleAdmin         Role = "admin"
	RoleGestor        Role = "gestor"
	RoleDesenvolvedor Role = "desenvolvedor"
	// RoleUser é quem está autenticado mas não tem papel global, numa rota
	// fora de projeto (por exemplo, um desenvolvedor listando os próprios
	// projetos).
	RoleUser Role = "usuario"
)

// Permission é uma ação protegida. Project indica que a decisão depende do
// papel no projeto da rota ({project}); senão, depende do papel global.
type Permission struct {
	Name    string
	Project bool
	roles   map[Role]bool
}

// Allows diz se o papel tem a permissão.
func (p Permission) Allows(r Role) bool {
	return p.roles[r]
}

func perm(name string, project bool, roles ...Role) Permission {
	m := make(map[Role]bool, len(roles))
	for _, r := range roles {
		m[r] = true
	}
	return Permission{Name: name, Project: project, roles: m}
}

// Permissões globais (fora de projeto).
var (
	// PermSession: qualquer usuário autenticado (login, me, troca de senha,
	// listar os próprios projetos).
	PermSession = perm("session", false, RoleSuperadmin, RoleAdmin, RoleUser)
	// Criar e excluir projetos: superadmin e admin.
	PermManageProjects = perm("projects.manage", false, RoleSuperadmin, RoleAdmin)
	// Criar e remover usuários e admins, resetar senha: só superadmin.
	PermManageUsers = perm("users.manage", false, RoleSuperadmin)
	// Seal do cofre: só superadmin (o unseal é público, decisão 2).
	PermSeal = perm("vault.seal", false, RoleSuperadmin)
	// Ver a auditoria: superadmin e admin.
	PermReadAudit = perm("audit.read", false, RoleSuperadmin, RoleAdmin)
)

// Permissões de projeto. Superadmin e admin têm o papel deles em todos os
// projetos; gestor e desenvolvedor, só nos projetos de que são membros.
var (
	// Usar no run (recebe os valores em lote) e listar os nomes: todos os
	// membros, inclusive o desenvolvedor. A regra é por rota: o desenvolvedor
	// recebe os valores pela rota do run, mas não por nenhuma outra. Isso
	// reduz a exposição, não a impede (ver decisão 13).
	PermUseSecrets       = perm("secrets.use", true, RoleSuperadmin, RoleAdmin, RoleGestor, RoleDesenvolvedor)
	PermListSecretNames  = perm("secrets.names", true, RoleSuperadmin, RoleAdmin, RoleGestor, RoleDesenvolvedor)
	PermReadSecretValue  = perm("secrets.read", true, RoleSuperadmin, RoleAdmin, RoleGestor)
	PermWriteSecrets     = perm("secrets.write", true, RoleSuperadmin, RoleAdmin, RoleGestor)  // criar, alterar, lixeira, restaurar
	PermPurgeSecrets     = perm("secrets.purge", true, RoleSuperadmin, RoleAdmin)              // excluir definitivamente
	PermManageMembers    = perm("members.manage", true, RoleSuperadmin, RoleAdmin, RoleGestor) // gestor: só desenvolvedores (conferido no handler)
	PermNominateManagers = perm("members.nominate", true, RoleSuperadmin, RoleAdmin)           // nomear gestores
)

// GlobalRole converte o papel global gravado no usuário ("superadmin",
// "admin" ou vazio) no papel usado fora de projeto.
func GlobalRole(stored string) Role {
	switch Role(stored) {
	case RoleSuperadmin, RoleAdmin:
		return Role(stored)
	}
	return RoleUser
}

// ProjectRole resolve o papel num projeto: o papel global, se houver
// (superadmin e admin valem em todos os projetos), senão o papel de membro.
// ok é false para quem não é membro e não tem papel global: para essa
// pessoa, o projeto é tratado como inexistente (decisão 6).
func ProjectRole(globalRole, memberRole string) (role Role, ok bool) {
	if r := GlobalRole(globalRole); r != RoleUser {
		return r, true
	}
	switch Role(memberRole) {
	case RoleGestor, RoleDesenvolvedor:
		return Role(memberRole), true
	}
	return "", false
}
