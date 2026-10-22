package auth

import (
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func newTestLimiter() (*Limiter, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	return NewLimiter(LoginMaxFailures, LoginBlock, c.now), c
}

func TestLimiterBlocksAfterMaxFailures(t *testing.T) {
	l, clock := newTestLimiter()
	for i := 0; i < LoginMaxFailures-1; i++ {
		l.Failure("email:a")
		if w := l.Wait("email:a"); w != 0 {
			t.Fatalf("bloqueou na falha %d", i+1)
		}
	}
	l.Failure("email:a") // 10ª falha seguida
	if w := l.Wait("email:a"); w != LoginBlock {
		t.Fatalf("espera = %v, quero %v", w, LoginBlock)
	}
	// Outras chaves não são afetadas.
	if w := l.Wait("email:b"); w != 0 {
		t.Fatalf("email:b bloqueado sem falhas: %v", w)
	}
	// Com várias chaves, vale a maior espera.
	clock.add(2 * time.Minute)
	if w := l.Wait("email:b", "email:a"); w != 3*time.Minute {
		t.Fatalf("espera = %v, quero 3m", w)
	}
	clock.add(3 * time.Minute)
	if w := l.Wait("email:a"); w != 0 {
		t.Fatalf("ainda bloqueado depois de 5 minutos: %v", w)
	}
}

func TestLimiterCounterExpires(t *testing.T) {
	l, clock := newTestLimiter()
	for i := 0; i < LoginMaxFailures-1; i++ {
		l.Failure("ip:1.2.3.4")
	}
	// Mais de 5 minutos sem falha: o contador recomeça.
	clock.add(LoginBlock + time.Second)
	l.Failure("ip:1.2.3.4")
	if w := l.Wait("ip:1.2.3.4"); w != 0 {
		t.Fatalf("bloqueou com falhas antigas: %v", w)
	}
}

func TestLimiterReset(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < LoginMaxFailures-1; i++ {
		l.Failure("email:a")
	}
	l.Reset("email:a")
	l.Failure("email:a")
	if w := l.Wait("email:a"); w != 0 {
		t.Fatalf("o login certo deveria zerar o contador: %v", w)
	}
}

func TestLimiterPrunesStaleEntries(t *testing.T) {
	l, clock := newTestLimiter()
	for i := range 10_000 {
		l.Failure("email:" + string(rune('a'+i%26)) + time.Duration(i).String())
	}
	clock.add(LoginBlock + time.Second)
	l.Failure("email:novo")
	if n := len(l.entries); n != 1 {
		t.Fatalf("entradas = %d, quero só a nova", n)
	}
}
