package api

import (
	"context"
	"sort"
	"sync"

	"github.com/heschaefer/envmem/internal/store"
)

// memStore implementa Store em memória, para testar a API sem banco. Segue
// o mesmo comportamento do store real (versões, ErrNotFound, vault_meta
// gravado uma única vez).
type memStore struct {
	mu      sync.Mutex
	meta    *store.VaultMeta
	secrets []store.SecretRow
}

func (m *memStore) GetVaultMeta(ctx context.Context) (store.VaultMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.meta == nil {
		return store.VaultMeta{}, store.ErrNotFound
	}
	return *m.meta, nil
}

func (m *memStore) InsertVaultMeta(ctx context.Context, meta store.VaultMeta) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.meta != nil {
		return false, nil
	}
	m.meta = &meta
	return true, nil
}

func (m *memStore) InsertSecretVersion(ctx context.Context, row store.SecretRow) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row.Version = 1
	for _, r := range m.secrets {
		if r.Project == row.Project && r.Key == row.Key && r.Version >= row.Version {
			row.Version = r.Version + 1
		}
	}
	m.secrets = append(m.secrets, row)
	return row.Version, nil
}

func (m *memStore) LatestSecrets(ctx context.Context, project string) ([]store.SecretRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	latest := map[string]store.SecretRow{}
	for _, r := range m.secrets {
		if r.Project == project && r.Version > latest[r.Key].Version {
			latest[r.Key] = r
		}
	}
	out := make([]store.SecretRow, 0, len(latest))
	for _, r := range latest {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
