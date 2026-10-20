package api

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/heschaefer/envmem/internal/store"
)

// memStore implementa Store em memória, para testar a API sem banco. Segue
// o mesmo comportamento do store real (versões, ErrNotFound, ErrConflict,
// ErrProjectNotEmpty, vault_meta gravado uma única vez).
type memStore struct {
	mu       sync.Mutex
	meta     *store.VaultMeta
	projects []store.Project
	nextID   int
	secrets  []store.SecretRow
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

func (m *memStore) CreateProject(ctx context.Context, name string) (store.Project, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.projects {
		if p.Name == name {
			return store.Project{}, store.ErrConflict
		}
	}
	m.nextID++
	p := store.Project{ID: fmt.Sprintf("id-%d", m.nextID), Name: name}
	m.projects = append(m.projects, p)
	return p, nil
}

func (m *memStore) ProjectByName(ctx context.Context, name string) (store.Project, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.projects {
		if p.Name == name {
			return p, nil
		}
	}
	return store.Project{}, store.ErrNotFound
}

func (m *memStore) ListProjects(ctx context.Context) ([]store.Project, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]store.Project(nil), m.projects...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *memStore) DeleteProject(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, p := range m.projects {
		if p.Name != name {
			continue
		}
		for _, r := range m.secrets {
			if r.ProjectID == p.ID {
				return store.ErrProjectNotEmpty
			}
		}
		m.projects = append(m.projects[:i], m.projects[i+1:]...)
		return nil
	}
	return store.ErrNotFound
}

func (m *memStore) InsertSecretVersion(ctx context.Context, row store.SecretRow) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row.Version = 1
	for _, r := range m.secrets {
		if r.ProjectID == row.ProjectID && r.Key == row.Key && r.Version >= row.Version {
			row.Version = r.Version + 1
		}
	}
	m.secrets = append(m.secrets, row)
	return row.Version, nil
}

func (m *memStore) LatestSecrets(ctx context.Context, projectID string) ([]store.SecretRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	latest := map[string]store.SecretRow{}
	for _, r := range m.secrets {
		if r.ProjectID == projectID && r.Version > latest[r.Key].Version {
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
