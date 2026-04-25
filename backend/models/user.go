package models

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
)

var (
	ErrEmailExists  = errors.New("email already exists")
	ErrUserNotFound = errors.New("user not found")
)

type User struct {
	ID           int64  `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
}

type userFile struct {
	NextID int64  `json:"next_id"`
	Users  []User `json:"users"`
}

type UserModel struct {
	mu           sync.RWMutex
	path         string
	nextID       int64
	usersByID    map[int64]User
	usersByEmail map[string]User
}

func NewUserModel(path string) (*UserModel, error) {
	if err := ensureDataFile(path); err != nil {
		return nil, err
	}
	m := &UserModel{
		path:         path,
		nextID:       1,
		usersByID:    make(map[int64]User),
		usersByEmail: make(map[string]User),
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *UserModel) load() error {
	b, err := os.ReadFile(m.path)
	if err != nil {
		return err
	}
	var uf userFile
	if err := json.Unmarshal(b, &uf); err != nil {
		return err
	}
	if uf.NextID <= 0 {
		uf.NextID = 1
	}
	m.nextID = uf.NextID
	for _, u := range uf.Users {
		m.usersByID[u.ID] = u
		m.usersByEmail[strings.ToLower(u.Email)] = u
	}
	return nil
}

func (m *UserModel) persistLocked() error {
	users := make([]User, 0, len(m.usersByID))
	for _, u := range m.usersByID {
		users = append(users, u)
	}
	b, err := json.MarshalIndent(userFile{NextID: m.nextID, Users: users}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, b, 0o644)
}

func (m *UserModel) Create(email, passwordHash string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	email = strings.ToLower(strings.TrimSpace(email))
	if _, ok := m.usersByEmail[email]; ok {
		return nil, ErrEmailExists
	}

	u := User{ID: m.nextID, Email: email, PasswordHash: passwordHash}
	m.nextID++
	m.usersByID[u.ID] = u
	m.usersByEmail[email] = u
	if err := m.persistLocked(); err != nil {
		delete(m.usersByID, u.ID)
		delete(m.usersByEmail, email)
		m.nextID--
		return nil, err
	}
	return &u, nil
}

func (m *UserModel) GetByEmail(email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.usersByEmail[strings.ToLower(strings.TrimSpace(email))]
	if !ok {
		return nil, ErrUserNotFound
	}
	uc := u
	return &uc, nil
}

func (m *UserModel) GetByID(id int64) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.usersByID[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	uc := u
	return &uc, nil
}
