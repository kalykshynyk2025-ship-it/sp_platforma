package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"sp_platforma/backend/models"
)

type AuthHandler struct {
	users     *models.UserModel
	jwtSecret []byte
}

type authRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type apiError struct {
	Error string `json:"error"`
}

func NewAuthHandler(users *models.UserModel, jwtSecret []byte) *AuthHandler {
	return &AuthHandler{users: users, jwtSecret: jwtSecret}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return
	}

	email := strings.TrimSpace(strings.ToLower(req.Email))
	if err := validateCredentials(email, req.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "failed to hash password"})
		return
	}

	user, err := h.users.Create(email, string(hashedPassword))
	if err != nil {
		if errors.Is(err, models.ErrEmailExists) {
			writeJSON(w, http.StatusConflict, apiError{Error: "user with this email already exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "failed to create user"})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "ok",
		"user": map[string]any{
			"id":    user.ID,
			"email": user.Email,
		},
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return
	}

	email := strings.TrimSpace(strings.ToLower(req.Email))
	if err := validateCredentials(email, req.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	user, err := h.users.GetByEmail(email)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "invalid credentials"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "failed to fetch user"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "invalid credentials"})
		return
	}

	token, err := h.makeJWT(user.ID, user.Email)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "failed to create token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"token":  token,
	})
}

func (h *AuthHandler) Profile(w http.ResponseWriter, r *http.Request) {
	ctxUser, ok := UserFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "unauthorized"})
		return
	}

	user, err := h.users.GetByID(ctxUser.ID)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, apiError{Error: "user not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "failed to fetch profile"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"user": map[string]any{
			"id":    user.ID,
			"email": user.Email,
		},
	})
}

func (h *AuthHandler) makeJWT(userID int64, email string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(h.jwtSecret)
}

func validateCredentials(email, password string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("invalid email")
	}
	if len(password) < 6 {
		return errors.New("password must contain at least 6 characters")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
