package models

import (
	"database/sql"
	"errors"
	"strings"
)

var (
	ErrEmailExists  = errors.New("email already exists")
	ErrUserNotFound = errors.New("user not found")
)

type User struct {
	ID           int64
	Email        string
	PasswordHash string
}

type UserModel struct {
	db *sql.DB
}

func NewUserModel(db *sql.DB) *UserModel {
	return &UserModel{db: db}
}

func (m *UserModel) Create(email, passwordHash string) (*User, error) {
	res, err := m.db.Exec(`INSERT INTO users (email, password_hash) VALUES (?, ?)`, email, passwordHash)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, ErrEmailExists
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &User{ID: id, Email: email, PasswordHash: passwordHash}, nil
}

func (m *UserModel) GetByEmail(email string) (*User, error) {
	var user User
	err := m.db.QueryRow(`SELECT id, email, password_hash FROM users WHERE email = ?`, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (m *UserModel) GetByID(id int64) (*User, error) {
	var user User
	err := m.db.QueryRow(`SELECT id, email, password_hash FROM users WHERE id = ?`, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}
