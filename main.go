package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"sp_platforma/backend/handlers"
	"sp_platforma/backend/middleware"
	"sp_platforma/backend/models"
)

func main() {
	port := getEnv("APP_PORT", "8080")
	jwtSecret := getEnv("JWT_SECRET", "change-me-in-production")
	dbPath := getEnv("DB_PATH", "./app_users.json")

	userModel, err := models.NewUserModel(dbPath)
	if err != nil {
		log.Fatalf("failed to initialize user storage: %v", err)
	}

	authHandler := handlers.NewAuthHandler(userModel, []byte(jwtSecret))
	authMiddleware := middleware.NewAuthMiddleware([]byte(jwtSecret))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", serveLanding)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("public/static"))))
	mux.Handle("/auth/", http.StripPrefix("/auth/", http.FileServer(http.Dir("public/auth"))))

	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("public", "auth", "index.html"))
	})
	mux.HandleFunc("GET /register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("public", "auth", "register.html"))
	})
	mux.HandleFunc("GET /profile", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("public", "auth", "profile.html"))
	})

	mux.HandleFunc("POST /api/register", authHandler.Register)
	mux.HandleFunc("POST /api/login", authHandler.Login)
	mux.Handle("GET /api/profile", authMiddleware.Auth(http.HandlerFunc(authHandler.Profile)))

	log.Printf("server is running on http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, withCORS(mux)); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func serveLanding(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join("public", "index.html"))
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
