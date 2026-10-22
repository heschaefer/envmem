// Comando envmem-server: o servidor central do envmem.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/heschaefer/envmem/internal/api"
	"github.com/heschaefer/envmem/internal/config"
	"github.com/heschaefer/envmem/internal/store"
	"github.com/heschaefer/envmem/internal/vault"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "keygen":
			cmdKeygen()
			return
		case "migrate":
			os.Exit(cmdMigrate())
		case "create-superadmin":
			os.Exit(cmdSuperadmin(os.Args[2:]))
		case "reset-password":
			os.Exit(cmdResetPassword(os.Args[2:]))
		}
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.LoadServer(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		logger.Error("configuração inválida", "err", err)
		os.Exit(2)
	}

	if err := serve(logger, cfg); err != nil {
		logger.Error("servidor encerrado com erro", "err", err)
		os.Exit(1)
	}
}

// serve conecta ao banco, confere a versão e os privilégios do usuário,
// sobe o servidor HTTPS (só TLS 1.3) e o encerra de forma ordenada ao
// receber SIGINT (Ctrl+C) ou SIGTERM.
func serve(logger *slog.Logger, cfg config.Server) error {
	// O certificado é carregado antes do banco: com arquivo errado, o
	// servidor nem chega a conectar.
	tlsConfig, err := config.ServerTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return err
	}

	startCtx, cancelStart := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStart()

	st, err := store.Open(startCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	// O servidor não migra (decisão 42): se o banco estiver atrasado em
	// relação ao binário, não sobe, em vez de rodar com estrutura velha.
	if err := st.CheckMigrated(startCtx); errors.Is(err, store.ErrPendingMigrations) {
		return errors.New("o banco tem migrações pendentes: rode envmem-server migrate (com DATABASE_MIGRATE_URL) antes de subir o servidor")
	} else if err != nil {
		return err
	}
	// Com o dono das tabelas, a auditoria "só de inserção" seria falsa: o
	// dono consegue devolver a si mesmo o DELETE. Melhor não subir.
	if err := st.CheckRestricted(startCtx); errors.Is(err, store.ErrPrivilegedUser) {
		return errors.New("DATABASE_URL usa um usuário que pode alterar ou apagar a auditoria (dono das tabelas ou superusuário); use o usuário restrito envmem_app")
	} else if err != nil {
		return err
	}
	logger.Info("banco conectado: versão atual e usuário restrito")

	srv := &http.Server{
		Addr: cfg.ListenAddr,
		// Não há porta HTTP sem TLS: a chave-mestra (unseal) e os segredos
		// trafegam nesta conexão.
		TLSConfig: tlsConfig,
		// O cofre nasce selado: a chave-mestra só chega pelo POST /v1/unseal
		// e fica só em memória. Reiniciar o servidor = selar.
		Handler: api.NewRouter(logger, api.FromStore(st), vault.New()),
		// Limites de tempo evitam que clientes lentos (ou maliciosos) prendam
		// conexões abertas indefinidamente.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Falhas de handshake (cliente sem TLS 1.3, certificado recusado)
		// aparecem aqui como aviso.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	// Certificado e chave já estão no TLSConfig, por isso os argumentos vazios.
	go func() { errCh <- srv.ListenAndServeTLS("", "") }()

	logger.Info("envmem-server no ar", "addr", cfg.ListenAddr, "tls", "1.3")

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	logger.Info("encerrando")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
