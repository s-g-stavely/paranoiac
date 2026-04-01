package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

var db *sql.DB

// SQL injection: user input concatenated directly into query.
func handleSearch(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "results returned")
}

// Command injection: user input passed directly to shell.
func handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(output)
}

// Path traversal: user controls file path with no sanitization.
func handleReadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	data, err := os.ReadFile("/var/data/" + filename)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Write(data)
}

// Hardcoded secret.
var apiKey = "sk-live-abc123secretkey456"

func main() {
	http.HandleFunc("/search", handleSearch)
	http.HandleFunc("/ping", handlePing)
	http.HandleFunc("/read", handleReadFile)
	http.ListenAndServe(":8080", nil)
}
