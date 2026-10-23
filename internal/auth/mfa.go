package auth

import "time"

// Política do MFA (decisão 36). O código é o TOTP (totp.go).

const (
	// MFAChallengeTTL é a validade do desafio do login em duas etapas: o
	// tempo entre acertar a senha e digitar o código.
	MFAChallengeTTL = 5 * time.Minute

	// MFAChallengeMaxFailures é quantos códigos errados um desafio aceita;
	// depois, ele é descartado e é preciso digitar a senha de novo (que
	// passa pelo argon2id e pelo limite do login).
	MFAChallengeMaxFailures = 5

	// MFAMaxFailures é quantos códigos errados seguidos travam o MFA da
	// conta até o reset por um superadmin. Só chega ao código quem acertou
	// a senha: com a trava, quem a roubou tem no máximo 10 palpites
	// (chance de acerto de cerca de 3 em 100 mil), em vez de 10 a cada 5
	// minutos, sem fim.
	MFAMaxFailures = 10
)

// RequiresMFA diz se o usuário precisa de MFA no login: superadmin e admin
// (papel global) e quem é gestor de algum projeto. O desenvolvedor, não
// (tabela de papéis).
func RequiresMFA(globalRole string, managesAnyProject bool) bool {
	switch GlobalRole(globalRole) {
	case RoleSuperadmin, RoleAdmin:
		return true
	}
	return managesAnyProject
}
