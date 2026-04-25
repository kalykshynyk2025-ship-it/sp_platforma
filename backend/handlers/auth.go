package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

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

type tokenClaims struct {
	UserID int64  `json:"user_id"`
	Email  string `json:"email"`
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
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

	hashedPassword := hashPassword(req.Password)
	user, err := h.users.Create(email, hashedPassword)
	if err != nil {
		if errors.Is(err, models.ErrEmailExists) {
			writeJSON(w, http.StatusConflict, apiError{Error: "user with this email already exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "failed to create user"})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"status": "ok", "user": map[string]any{"id": user.ID, "email": user.Email}})
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
	if err != nil || !verifyPassword(user.PasswordHash, req.Password) {
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "invalid credentials"})
		return
	}

	token, err := MakeToken(h.jwtSecret, user.ID, user.Email)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "failed to create token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "token": token})
}

func (h *AuthHandler) Profile(w http.ResponseWriter, r *http.Request) {
	ctxUser, ok := UserFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "unauthorized"})
		return
	}
	user, err := h.users.GetByID(ctxUser.ID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, apiError{Error: "user not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "user": map[string]any{"id": user.ID, "email": user.Email}})
}

func MakeToken(secret []byte, userID int64, email string) (string, error) {
	claims := tokenClaims{UserID: userID, Email: email, Exp: time.Now().Add(24 * time.Hour).Unix(), Iat: time.Now().Unix()}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := sign(secret, payloadB64)
	return payloadB64 + "." + sig, nil
}

func ParseToken(secret []byte, token string) (int64, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return 0, "", errors.New("invalid token format")
	}
	if !hmac.Equal([]byte(sign(secret, parts[0])), []byte(parts[1])) {
		return 0, "", errors.New("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, "", err
	}
	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, "", err
	}
	if claims.Exp < time.Now().Unix() {
		return 0, "", errors.New("token expired")
	}
	return claims.UserID, claims.Email, nil
}

func sign(secret []byte, data string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func hashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

func verifyPassword(hash, password string) bool {
	return hmac.Equal([]byte(hash), []byte(hashPassword(password)))
}

func validateCredentials(email, password string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("invalid email")
	}
	if len(password) < 6 {
		return errors.New("password must contain at least 6 characters")
	}
	if strings.Contains(password, " ") {
		return fmt.Errorf("password must not contain spaces")
	}
	if _, err := strconv.ParseInt(email, 10, 64); err == nil {
		return fmt.Errorf("invalid email")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
