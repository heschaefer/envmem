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
)

func main() {
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

// serve conecta ao banco, aplica as migrações, sobe o servidor HTTP e o
// encerra de forma ordenada ao receber SIGINT (Ctrl+C) ou SIGTERM.
func serve(logger *slog.Logger, cfg config.Server) error {
	startCtx, cancelStart := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStart()

	st, err := store.Open(startCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(startCtx); err != nil {
		return err
	}
	logger.Info("banco conectado e migrações aplicadas")

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: api.NewRouter(logger),
		// Limites de tempo evitam que clientes lentos (ou maliciosos) prendam
		// conexões abertas indefinidamente.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	// TLS 1.3 entra na Fatia 3. Até lá, o tráfego vai em texto claro, então
	// o servidor só deve rodar dentro do container de desenvolvimento.
	logger.Info("envmem-server no ar", "addr", cfg.ListenAddr, "tls", false)

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
