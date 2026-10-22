package api

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/heschaefer/envmem/internal/store"
)

// memStore implementa Store em memória, para testar a API sem banco. Segue
// o mesmo comportamento do store real (versões, ErrNotFound, ErrConflict,
// ErrProjectNotEmpty, vault_meta gravado uma única vez).
type memStore struct {
	mu       sync.Mutex
	now      func() time.Time // o mesmo relógio do roteador
	meta     *store.VaultMeta
	projects []store.Project
	nextID   int
	secrets  []store.SecretRow
	users    []store.User
	sessions []memSession
	members  map[[2]string]string // (projeto, usuário) -> papel
}

func (m *memStore) MemberRole(ctx context.Context, projectID, userID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if role, ok := m.members[[2]string{projectID, userID}]; ok {
		return role, nil
	}
	return "", store.ErrNotFound
}

// setMember grava um membro direto no store (como o SetMember).
func (m *memStore) setMember(projectID, userID, role string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.members == nil {
		m.members = map[[2]string]string{}
	}
	m.members[[2]string{projectID, userID}] = role
}

func (m *memStore) ProjectsForMember(ctx context.Context, userID string) ([]store.ProjectMembership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.ProjectMembership
	for _, p := range m.projects {
		if role, ok := m.members[[2]string{p.ID, userID}]; ok {
			out = append(out, store.ProjectMembership{Project: p, Role: role})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type memSession struct {
	tokenHash []byte
	userID    string
	expiresAt time.Time
}

// addUser cria um usuário direto no store, como o create-superadmin (ou,
// mais tarde, o POST /users) faria.
func (m *memStore) addUser(u store.User) store.User {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	u.ID = fmt.Sprintf("user-%d", m.nextID)
	m.users = append(m.users, u)
	return u
}

func (m *memStore) UserByEmail(ctx context.Context, email string) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return store.User{}, store.ErrNotFound
}

func (m *memStore) CreateSession(ctx context.Context, tokenHash []byte, userID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions = append(m.sessions, memSession{tokenHash, userID, expiresAt})
	return nil
}

func (m *memStore) UserBySession(ctx context.Context, tokenHash []byte) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sess := range m.sessions {
		if bytes.Equal(sess.tokenHash, tokenHash) && m.now().Before(sess.expiresAt) {
			for _, u := range m.users {
				if u.ID == sess.userID {
					return u, nil
				}
			}
		}
	}
	return store.User{}, store.ErrNotFound
}

func (m *memStore) DeleteSession(ctx context.Context, tokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions = filterSessions(m.sessions, func(s memSession) bool { return !bytes.Equal(s.tokenHash, tokenHash) })
	return nil
}

func (m *memStore) ChangePassword(ctx context.Context, userID, passwordHash string, keepTokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.users {
		if m.users[i].ID == userID {
			m.users[i].PasswordHash = passwordHash
			m.users[i].TempPasswordExpiresAt = nil
			m.sessions = filterSessions(m.sessions, func(s memSession) bool {
				return s.userID != userID || bytes.Equal(s.tokenHash, keepTokenHash)
			})
			return nil
		}
	}
	return store.ErrNotFound
}

func filterSessions(in []memSession, keep func(memSession) bool) []memSession {
	var out []memSession
	for _, s := range in {
		if keep(s) {
			out = append(out, s)
		}
	}
	return out
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
	row.CreatedAt = m.now()
	m.secrets = append(m.secrets, row)
	// Como o store real: sai da lixeira e guarda só as últimas versões.
	var kept []store.SecretRow
	for _, r := range m.secrets {
		if r.ProjectID == row.ProjectID && r.Key == row.Key {
			if r.Version <= row.Version-store.SecretRetention {
				continue
			}
			r.DeletedAt = nil
		}
		kept = append(kept, r)
	}
	m.secrets = kept
	return row.Version, nil
}

func (m *memStore) LatestSecrets(ctx context.Context, projectID string) ([]store.SecretRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	latest := map[string]store.SecretRow{}
	for _, r := range m.secrets {
		if r.ProjectID == projectID && r.DeletedAt == nil && r.Version > latest[r.Key].Version {
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

func (m *memStore) ListMembers(ctx context.Context, projectID string) ([]store.Member, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Member
	for _, u := range m.users {
		if role, ok := m.members[[2]string{projectID, u.ID}]; ok {
			out = append(out, store.Member{UserID: u.ID, Email: u.Email, Role: role})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

func (m *memStore) SetMember(ctx context.Context, projectID, userID, role string) error {
	m.setMember(projectID, userID, role)
	return nil
}

func (m *memStore) RemoveMember(ctx context.Context, projectID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{projectID, userID}
	if _, ok := m.members[k]; !ok {
		return store.ErrNotFound
	}
	delete(m.members, k)
	return nil
}

func (m *memStore) ListUsers(ctx context.Context) ([]store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]store.User(nil), m.users...)
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

func (m *memStore) CreateUser(ctx context.Context, email, globalRole, passwordHash string, tempExpiresAt time.Time) (store.User, error) {
	if _, err := m.UserByEmail(ctx, email); err == nil {
		return store.User{}, store.ErrConflict
	}
	return m.addUser(store.User{Email: email, GlobalRole: globalRole, PasswordHash: passwordHash, TempPasswordExpiresAt: &tempExpiresAt}), nil
}

func (m *memStore) DeleteUser(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	supers, idx := 0, -1
	for i, u := range m.users {
		if u.GlobalRole == store.RoleSuperadmin {
			supers++
		}
		if u.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		return store.ErrNotFound
	}
	if m.users[idx].GlobalRole == store.RoleSuperadmin && supers == 1 {
		return store.ErrLastSuperadmin
	}
	m.users = append(m.users[:idx], m.users[idx+1:]...)
	m.sessions = filterSessions(m.sessions, func(s memSession) bool { return s.userID != id })
	for k := range m.members {
		if k[1] == id {
			delete(m.members, k)
		}
	}
	return nil
}

func (m *memStore) ResetPassword(ctx context.Context, id, passwordHash string, tempExpiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.users {
		if m.users[i].ID == id {
			m.users[i].PasswordHash = passwordHash
			m.users[i].TempPasswordExpiresAt = &tempExpiresAt
			m.sessions = filterSessions(m.sessions, func(s memSession) bool { return s.userID != id })
			return nil
		}
	}
	return store.ErrNotFound
}

func (m *memStore) SecretVersion(ctx context.Context, projectID, key string, version int) (store.SecretRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best store.SecretRow
	for _, r := range m.secrets {
		if r.ProjectID == projectID && r.Key == key && r.DeletedAt == nil &&
			(version == 0 && r.Version > best.Version || r.Version == version) {
			best = r
		}
	}
	if best.Version == 0 {
		return store.SecretRow{}, store.ErrNotFound
	}
	return best, nil
}

func (m *memStore) SecretsMeta(ctx context.Context, projectID string) ([]store.SecretMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byKey := map[string]*store.SecretMeta{}
	for _, r := range m.secrets {
		if r.ProjectID != projectID || r.DeletedAt != nil {
			continue
		}
		meta := byKey[r.Key]
		if meta == nil {
			meta = &store.SecretMeta{Key: r.Key}
			byKey[r.Key] = meta
		}
		meta.Versions++
		if r.Version > meta.Version {
			meta.Version, meta.UpdatedAt = r.Version, r.CreatedAt
		}
	}
	out := make([]store.SecretMeta, 0, len(byKey))
	for _, meta := range byKey {
		out = append(out, *meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// trashOp aplica f às versões de (projeto, chave) com o estado de lixeira
// indicado e devolve a maior versão afetada, ou ErrNotFound.
func (m *memStore) trashOp(projectID, key string, inTrash bool, f func(i int)) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	maxV := 0
	for i := len(m.secrets) - 1; i >= 0; i-- {
		r := m.secrets[i]
		if r.ProjectID == projectID && r.Key == key && (r.DeletedAt != nil) == inTrash {
			maxV = max(maxV, r.Version)
			f(i)
		}
	}
	if maxV == 0 {
		return 0, store.ErrNotFound
	}
	return maxV, nil
}

func (m *memStore) TrashSecret(ctx context.Context, projectID, key string) (int, error) {
	now := m.now()
	return m.trashOp(projectID, key, false, func(i int) { m.secrets[i].DeletedAt = &now })
}

func (m *memStore) RestoreSecret(ctx context.Context, projectID, key string) (int, error) {
	return m.trashOp(projectID, key, true, func(i int) { m.secrets[i].DeletedAt = nil })
}

func (m *memStore) PurgeSecret(ctx context.Context, projectID, key string) (int, error) {
	return m.trashOp(projectID, key, true, func(i int) { m.secrets = append(m.secrets[:i], m.secrets[i+1:]...) })
}

func (m *memStore) ListTrash(ctx context.Context, projectID string) ([]store.TrashedSecret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byKey := map[string]store.TrashedSecret{}
	for _, r := range m.secrets {
		if r.ProjectID == projectID && r.DeletedAt != nil && r.Version > byKey[r.Key].Version {
			byKey[r.Key] = store.TrashedSecret{Key: r.Key, Version: r.Version, DeletedAt: *r.DeletedAt}
		}
	}
	out := make([]store.TrashedSecret, 0, len(byKey))
	for _, t := range byKey {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
