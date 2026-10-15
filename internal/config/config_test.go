package config

import (
	"io"
	"testing"
)

func TestLoadServerPrecedence(t *testing.T) {
	tests := []struct {
		name string
		env  string
		args []string
		want string
	}{
		{name: "padrão", env: "", args: nil, want: ":8080"},
		{name: "variável de ambiente", env: ":9000", args: nil, want: ":9000"},
		{name: "flag vence a variável", env: ":9000", args: []string{"-listen", ":9100"}, want: ":9100"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ENVMEM_LISTEN_ADDR", tt.env)
			cfg, err := LoadServer(tt.args, io.Discard)
			if err != nil {
				t.Fatalf("LoadServer: %v", err)
			}
			if cfg.ListenAddr != tt.want {
				t.Errorf("ListenAddr = %q, quero %q", cfg.ListenAddr, tt.want)
			}
		})
	}
}

func TestLoadServerUnknownFlag(t *testing.T) {
	if _, err := LoadServer([]string{"-nao-existe"}, io.Discard); err == nil {
		t.Fatal("esperava erro para flag desconhecida")
	}
}
