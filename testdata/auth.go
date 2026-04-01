package main

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// Weak hashing: MD5 for passwords.
func hashPassword(password string) string {
	h := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", h)
}

// Timing side-channel: string comparison on secrets is not constant-time.
func validateToken(provided, actual string) bool {
	if len(provided) != len(actual) {
		return false
	}
	for i := range provided {
		if provided[i] != actual[i] {
			return false
		}
	}
	return true
}

// Insecure session token generation: predictable seed.
func generateSessionToken() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(99999))
	return fmt.Sprintf("session-%d-%d", time.Now().Unix(), n)
}

// Missing auth check: admin endpoint has no authentication.
func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	// No authentication or authorization check
	fmt.Fprintf(w, "deleted user %s", userID)
}

// XSS: reflecting user input without escaping.
func handleGreet(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Hello, %s!</h1>", name)
}
