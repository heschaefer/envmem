package main

import (
	"slices"
	"strings"
	"testing"
)

func TestSplitCommand(t *testing.T) {
	tests := []struct {
		line string
		want []string
	}{
		{"npm run dev", []string{"npm", "run", "dev"}},
		{"  npm\trun   dev  ", []string{"npm", "run", "dev"}},
		{"npm run dev -- --port 3000", []string{"npm", "run", "dev", "--", "--port", "3000"}},
		{`git commit -m 'mensagem com espaços'`, []string{"git", "commit", "-m", "mensagem com espaços"}},
		{`echo "aspas \"dentro\" e \\ barra"`, []string{"echo", `aspas "dentro" e \ barra`}},
		{`echo "\n fica como está"`, []string{"echo", `\n fica como está`}},
		{`echo a\ b`, []string{"echo", "a b"}},
		{`prog --nome=''`, []string{"prog", "--nome="}},
		{`prog ''`, []string{"prog", ""}},
		{`prog a'b'"c"`, []string{"prog", "abc"}},
		// Entre aspas, os caracteres do shell são texto comum.
		{`psql -c 'select 1; select 2'`, []string{"psql", "-c", "select 1; select 2"}},
		{`echo '$DB_PASSWORD'`, []string{"echo", "$DB_PASSWORD"}},
		{`sh -c 'echo $DB_PASSWORD | wc -c'`, []string{"sh", "-c", "echo $DB_PASSWORD | wc -c"}},
	}
	for _, tt := range tests {
		got, err := splitCommand(tt.line)
		if err != nil || !slices.Equal(got, tt.want) {
			t.Errorf("splitCommand(%q) = %q, %v; quero %q", tt.line, got, err, tt.want)
		}
	}
}

func TestSplitCommandRejects(t *testing.T) {
	tests := []struct {
		line, wantErr string
	}{
		{"", "digite um comando"},
		{"   ", "digite um comando"},
		{"echo 'aberta", "aspa simples"},
		{`echo "aberta`, "aspa dupla"},
		{`echo \`, "barra invertida"},
		// Sem shell, nada disso funcionaria como o usuário espera.
		{"npm start | tee log", "sem shell"},
		{"npm start > log", "sem shell"},
		{"cat < arquivo", "sem shell"},
		{"make; make test", "sem shell"},
		{"servidor &", "sem shell"},
		{"echo $DB_PASSWORD", "sem shell"},
		{"echo `id`", "sem shell"},
	}
	for _, tt := range tests {
		got, err := splitCommand(tt.line)
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("splitCommand(%q) = %q, %v; quero erro com %q", tt.line, got, err, tt.wantErr)
		}
	}
}
