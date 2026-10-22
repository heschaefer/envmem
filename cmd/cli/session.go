package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// O token de sessão fica em ~/.config/envmem/token (decisão 4), com
// permissão 600: só o próprio usuário lê. É o único arquivo com credencial
// que o CLI grava; o run nunca cria arquivos.

// errNoSession indica que não há token gravado (nunca fez login, ou fez
// logout).
var errNoSession = errors.New("nenhuma sessão: rode envmem login")

// configDir é ~/.config/envmem, ou $XDG_CONFIG_HOME/envmem se definida. É o
// mesmo caminho no Linux e no macOS (os.UserConfigDir usaria outro no
// macOS), para bater com a documentação.
func configDir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("localizar a pasta do usuário: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "envmem"), nil
}

func tokenPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "token"), nil
}

// saveToken grava o token, com permissão 600 (ver writePrivateFile).
func saveToken(token string) error {
	path, err := tokenPath()
	if err != nil {
		return err
	}
	if err := writePrivateFile(path, []byte(token+"\n")); err != nil {
		return fmt.Errorf("gravar o token: %w", err)
	}
	return nil
}

// writePrivateFile grava data em path. O arquivo é criado já com permissão
// 600 (o os.CreateTemp cria assim), num nome temporário na mesma pasta, e
// só depois renomeado: não existe instante em que o conteúdo esteja num
// arquivo com permissão mais aberta, nem um arquivo pela metade se algo
// falhar.
func writePrivateFile(path string, data []byte) error {
	// 700: além do arquivo, a pasta também só é acessível pelo usuário.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // sem efeito depois do rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// loadToken lê o token gravado. Como o ssh faz com chaves privadas, recusa
// um arquivo que outros usuários possam ler: se a permissão foi aberta,
// é melhor o usuário saber do que o CLI seguir usando um token exposto.
func loadToken() (string, error) {
	path, err := tokenPath()
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", errNoSession
	}
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("o arquivo %s pode ser lido por outros usuários (permissão %o); "+
			"rode envmem logout e entre de novo, ou corrija com chmod 600", path, info.Mode().Perm())
	}
	return readToken(path)
}

// readToken lê o arquivo do token sem conferir a permissão. Só o logout
// usa direto: mesmo com a permissão errada, a sessão deve ser revogada.
func readToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", errNoSession
	}
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", errNoSession
	}
	return token, nil
}

// deleteToken apaga o arquivo do token. Não existir não é erro.
func deleteToken() error {
	path, err := tokenPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
