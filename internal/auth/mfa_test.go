package auth

import "testing"

func TestRequiresMFA(t *testing.T) {
	tests := []struct {
		globalRole string
		gestor     bool
		want       bool
	}{
		{"superadmin", false, true},
		{"admin", false, true},
		{"", true, true},   // gestor de algum projeto
		{"", false, false}, // só desenvolvedor (ou sem projetos)
		{"desconhecido", false, false},
	}
	for _, tt := range tests {
		if got := RequiresMFA(tt.globalRole, tt.gestor); got != tt.want {
			t.Errorf("RequiresMFA(%q, %v) = %v, quero %v", tt.globalRole, tt.gestor, got, tt.want)
		}
	}
}
