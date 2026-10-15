package envname

import (
	"errors"
	"testing"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		name string
		want error // nil, ErrInvalid ou ErrBlocked
	}{
		{"DB_PASSWORD", nil},
		{"API_KEY_2", nil},
		{"_PRIVATE", nil},
		{"db_password", nil},
		{"GITHUB_TOKEN", nil}, // não é GIT_
		{"PATHNAME", nil},     // só PATH exato é bloqueado

		{"", ErrInvalid},
		{"1A", ErrInvalid},
		{"A=B", ErrInvalid},
		{"A B", ErrInvalid},
		{"A-B", ErrInvalid},
		{"BASH_FUNC_ls%%", ErrInvalid},
		{"SENHA_Ç", ErrInvalid},

		{"PATH", ErrBlocked},
		{"path", ErrBlocked},
		{"BASH_ENV", ErrBlocked},
		{"NODE_OPTIONS", ErrBlocked},
		{"LD_PRELOAD", ErrBlocked},
		{"LD_LIBRARY_PATH", ErrBlocked},
		{"DYLD_INSERT_LIBRARIES", ErrBlocked},
		{"GIT_SSH_COMMAND", ErrBlocked},
		{"npm_config_script_shell", ErrBlocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(tt.name)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("Check(%q) = %v, quero nil", tt.name, err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("Check(%q) = %v, quero %v", tt.name, err, tt.want)
			}
		})
	}
}
