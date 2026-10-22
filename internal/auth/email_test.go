package auth

import "testing"

func TestNormalizeEmail(t *testing.T) {
	ok := map[string]string{
		"fulano@empresa.com":       "fulano@empresa.com",
		"  Fulano@Empresa.COM\n":   "fulano@empresa.com",
		"henryque.schaefer@ids.br": "henryque.schaefer@ids.br",
	}
	for in, want := range ok {
		if got, err := NormalizeEmail(in); err != nil || got != want {
			t.Errorf("NormalizeEmail(%q) = %q, %v; quero %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "fulano", "@empresa.com", "Fulano <f@e.com>", "a@b.com, c@d.com", "fulano@"} {
		if got, err := NormalizeEmail(in); err == nil {
			t.Errorf("NormalizeEmail(%q) = %q; esperava erro", in, got)
		}
	}
}
