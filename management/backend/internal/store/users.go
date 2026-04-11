package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID              int64      `json:"id"`
	Username        string     `json:"username"`
	Role            string     `json:"role"`
	PasswordChanged bool       `json:"password_changed"`
	CreatedAt       time.Time  `json:"created_at"`
	LastLogin       *time.Time `json:"last_login"`
}

func (db *DB) GetUserByUsername(ctx context.Context, username string) (*User, string, error) {
	var u User
	var hash string
	err := db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, role, password_changed, created_at, last_login
		FROM users WHERE username = $1
	`, username).Scan(&u.ID, &u.Username, &hash, &u.Role, &u.PasswordChanged, &u.CreatedAt, &u.LastLogin)
	if err == sql.ErrNoRows {
		return nil, "", fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, "", err
	}
	return &u, hash, nil
}

func (db *DB) GetUserByID(ctx context.Context, id int64) (*User, error) {
	var u User
	err := db.QueryRowContext(ctx, `
		SELECT id, username, role, password_changed, created_at, last_login
		FROM users WHERE id = $1
	`, id).Scan(&u.ID, &u.Username, &u.Role, &u.PasswordChanged, &u.CreatedAt, &u.LastLogin)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (db *DB) UpdateLastLogin(ctx context.Context, userID int64) error {
	_, err := db.ExecContext(ctx, `UPDATE users SET last_login = NOW() WHERE id = $1`, userID)
	return err
}

func (db *DB) ChangePassword(ctx context.Context, userID int64, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
		UPDATE users SET password_hash = $1, password_changed = TRUE WHERE id = $2
	`, string(hash), userID)
	return err
}

func (db *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, username, role, password_changed, created_at, last_login
		FROM users ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.PasswordChanged, &u.CreatedAt, &u.LastLogin); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (db *DB) CreateUser(ctx context.Context, username, password, role string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return nil, err
	}
	var u User
	err = db.QueryRowContext(ctx, `
		INSERT INTO users (username, password_hash, role)
		VALUES ($1, $2, $3)
		RETURNING id, username, role, password_changed, created_at, last_login
	`, username, string(hash), role).Scan(&u.ID, &u.Username, &u.Role, &u.PasswordChanged, &u.CreatedAt, &u.LastLogin)
	return &u, err
}

func (db *DB) DeleteUser(ctx context.Context, id int64) error {
	_, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = $1 AND username != 'admin'`, id)
	return err
}

// SeedAdmin creates the default admin user if no users exist.
func (db *DB) SeedAdmin(ctx context.Context) error {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("changeme"), 12)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO users (username, password_hash, role, password_changed)
		VALUES ('admin', $1, 'admin', FALSE)
		ON CONFLICT (username) DO NOTHING
	`, string(hash))
	return err
}

func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(h), err
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
