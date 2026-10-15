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
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.LoadServer(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		os.Exit(2)
	}

	if err := serve(logger, cfg); err != nil {
		logger.Error("servidor encerrado com erro", "err", err)
		os.Exit(1)
	}
}

// serve sobe o servidor HTTP e o encerra de forma ordenada ao receber
// SIGINT (Ctrl+C) ou SIGTERM (docker stop).
func serve(logger *slog.Logger, cfg config.Server) error {
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
