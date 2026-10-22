package auth

import (
	"sync"
	"time"
)

// Limites de tentativas de login (decisão 45): depois de LoginMaxFailures
// falhas seguidas, novas tentativas são recusadas por LoginBlock. O
// contador também zera depois de LoginBlock sem nenhuma falha.
const (
	LoginMaxFailures = 10
	LoginBlock       = 5 * time.Minute
)

// Limiter conta falhas de login por chave (por exemplo, "email:..." e
// "ip:..."), só em memória: os contadores zeram quando o servidor
// reinicia. Não bloqueia a conta: só faz esperar, para que ninguém consiga
// deixar a conta de outra pessoa indisponível por tempo indeterminado.
type Limiter struct {
	mu      sync.Mutex
	max     int
	block   time.Duration
	now     func() time.Time
	entries map[string]*limiterEntry
}

type limiterEntry struct {
	failures     int
	lastFailure  time.Time
	blockedUntil time.Time
}

// NewLimiter devolve um limitador com max falhas e espera de block. now é
// o relógio (time.Now em produção; os testes passam um relógio falso).
func NewLimiter(max int, block time.Duration, now func() time.Time) *Limiter {
	return &Limiter{max: max, block: block, now: now, entries: map[string]*limiterEntry{}}
}

// Wait devolve quanto tempo falta para alguma das chaves poder tentar de
// novo, ou zero se todas estão liberadas.
func (l *Limiter) Wait(keys ...string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var wait time.Duration
	for _, k := range keys {
		if e := l.entries[k]; e != nil && now.Before(e.blockedUntil) {
			wait = max(wait, e.blockedUntil.Sub(now))
		}
	}
	return wait
}

// Failure registra uma falha em cada chave. Ao chegar a max falhas
// seguidas, a chave fica bloqueada por block, e o contador recomeça.
func (l *Limiter) Failure(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.prune(now)
	for _, k := range keys {
		e := l.entries[k]
		if e == nil || now.Sub(e.lastFailure) > l.block {
			e = &limiterEntry{}
			l.entries[k] = e
		}
		e.failures++
		e.lastFailure = now
		if e.failures >= l.max {
			e.blockedUntil = now.Add(l.block)
			e.failures = 0
		}
	}
}

// Reset zera as chaves, depois de um login bem-sucedido.
func (l *Limiter) Reset(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.entries, k)
	}
}

// prune descarta as chaves sem falha recente nem bloqueio, para que o mapa
// não cresça sem limite com e-mails inventados. Só roda quando o mapa
// passa de um tamanho, para não percorrê-lo a cada falha.
func (l *Limiter) prune(now time.Time) {
	if len(l.entries) < 10_000 {
		return
	}
	for k, e := range l.entries {
		if now.Sub(e.lastFailure) > l.block && !now.Before(e.blockedUntil) {
			delete(l.entries, k)
		}
	}
}
