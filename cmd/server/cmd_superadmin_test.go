package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
)

// fakeCreator guarda o que recebeu e devolve err.
type fakeCreator struct {
	email, hash string
	err         error
}

func (f *fakeCreator) CreateFirstSuperadmin(ctx context.Context, email, hash string) (store.User, error) {
	f.email, f.hash = email, hash
	return store.User{}, f.err
}

func TestCreateSuperadmin(t *testing.T) {
	f := &fakeCreator{}
	password := []byte("uma senha bem longa")
	email, err := createSuperadmin(context.Background(), f, "  Admin@Empresa.com ", password)
	if err != nil {
		t.Fatalf("createSuperadmin: %v", err)
	}
	if email != "admin@empresa.com" || f.email != "admin@empresa.com" {
		t.Errorf("e-mail = %q / %q, quero normalizado", email, f.email)
	}
	// O store recebe o hash, nunca a senha.
	if strings.Contains(f.hash, string(password)) {
		t.Fatal("o store recebeu a senha em claro")
	}
	if ok, _ := auth.VerifyPassword(f.hash, password); !ok {
		t.Fatal("o hash gravado não confere com a senha")
	}
}

func TestCreateSuperadminRejects(t *testing.T) {
	ctx := context.Background()
	long := []byte("uma senha bem longa")

	if _, err := createSuperadmin(ctx, &fakeCreator{}, "não é e-mail", long); !errors.Is(err, auth.ErrInvalidEmail) {
		t.Errorf("e-mail inválido: %v", err)
	}
	f := &fakeCreator{}
	if _, err := createSuperadmin(ctx, f, "a@b.com", []byte("curta")); !errors.Is(err, auth.ErrPasswordPolicy) {
		t.Errorf("senha curta: %v", err)
	}
	if f.hash != "" {
		t.Error("com senha recusada, nada deveria chegar ao store")
	}
	if _, err := createSuperadmin(ctx, &fakeCreator{err: store.ErrSuperadminExists}, "a@b.com", long); err == nil || !strings.Contains(err.Error(), "já existe um superadmin") {
		t.Errorf("superadmin existente: %v", err)
	}
}

func TestReadLine(t *testing.T) {
	for in, want := range map[string]string{
		"senha com espaços\n": "senha com espaços",
		"senha\r\n":           "senha",
		"sem quebra":          "sem quebra",
		"primeira\nsegunda\n": "primeira",
	} {
		got, err := readLine(strings.NewReader(in))
		if err != nil || string(got) != want {
			t.Errorf("readLine(%q) = %q, %v; quero %q", in, got, err, want)
		}
	}
}

type fakeResetter struct {
	email, hash string
	expires     time.Time
	err         error
}

func (f *fakeResetter) ResetLoneSuperadminPassword(ctx context.Context, email, hash string, exp time.Time) (store.User, error) {
	f.email, f.hash, f.expires = email, hash, exp
	return store.User{}, f.err
}

func TestResetLoneSuperadmin(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	f := &fakeResetter{}
	email, err := resetLoneSuperadmin(context.Background(), f, "Admin@Empresa.com", []byte("temporaria bem longa"), now)
	if err != nil || email != "admin@empresa.com" {
		t.Fatalf("reset = %q, %v", email, err)
	}
	if !f.expires.Equal(now.Add(72 * time.Hour)) {
		t.Errorf("validade = %v, quero 72 horas", f.expires)
	}
	if ok, _ := auth.VerifyPassword(f.hash, []byte("temporaria bem longa")); !ok {
		t.Error("o hash não confere com a senha")
	}

	for errIn, want := range map[error]string{
		store.ErrNotSuperadmin:    "só redefine a senha de superadmin",
		store.ErrSuperadminExists: "há outro superadmin",
		store.ErrNotFound:         "não existe usuário",
	} {
		if _, err := resetLoneSuperadmin(context.Background(), &fakeResetter{err: errIn}, "a@b.com", []byte("temporaria bem longa"), now); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: erro = %v, quero %q", errIn, err, want)
		}
	}
	if _, err := resetLoneSuperadmin(context.Background(), &fakeResetter{}, "a@b.com", []byte("curta"), now); !errors.Is(err, auth.ErrPasswordPolicy) {
		t.Errorf("senha curta: %v", err)
	}
}
