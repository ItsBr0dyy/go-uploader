package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

const (
	configPath = "config/config.json"
	uploadDir  = "./uploads"
	maxSize    = 10 << 20 // 10 MB
	ttl        = 24 * time.Hour
)

type Config struct {
	APIKey string `json:"api_key"`
	Port   int    `json:"port"`
}

var (
	cfg     Config
	keyHash [32]byte

	allowed = map[string]string{
		"image/png":  ".png",
		"image/jpeg": ".jpg",
		"image/gif":  ".gif",
		"image/webp": ".webp",
	}
	idRe = regexp.MustCompile(`^[a-f0-9]{16}$`)
)

func loadConfig() {
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("could not read %s: %v", configPath, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("invalid %s: %v", configPath, err)
	}
	if cfg.APIKey == "" || cfg.APIKey == "large-string-brody" {
		log.Fatalf("set a real api_key in %s", configPath)
	}
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	keyHash = sha256.Sum256([]byte(cfg.APIKey))
}

func authorized(r *http.Request) bool {
	got := r.Header.Get("API-Key")
	if got == "" {
		return false
	}
	gotHash := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(gotHash[:], keyHash[:]) == 1
}

func main() {
	loadConfig()

	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		log.Fatal(err)
	}

	go cleanupLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /upload", handleUpload)
	mux.HandleFunc("GET /{id}", handleServe)

	addr := ":" + strconv.Itoa(cfg.Port)
	log.Println("listening on", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if !authorized(r) {
		jsonErr(w, http.StatusUnauthorized, "invalid or missing API key")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSize+1024)
	if err := r.ParseMultipartForm(maxSize); err != nil {
		jsonErr(w, http.StatusRequestEntityTooLarge, "file too large (max 10MB)")
		return
	}

	file, _, err := r.FormFile("image")
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "missing 'image' field")
		return
	}
	defer file.Close()

	head := make([]byte, 512)
	n, _ := file.Read(head)
	ext, ok := allowed[http.DetectContentType(head[:n])]
	if !ok {
		jsonErr(w, http.StatusUnsupportedMediaType, "only png, jpg, gif, webp allowed")
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		jsonErr(w, http.StatusInternalServerError, "read error")
		return
	}

	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		jsonErr(w, http.StatusInternalServerError, "id error")
		return
	}
	id := hex.EncodeToString(idBytes)

	dst, err := os.Create(filepath.Join(uploadDir, id+ext))
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "save error")
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		os.Remove(dst.Name())
		jsonErr(w, http.StatusInternalServerError, "save error")
		return
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"url":        scheme + "://" + r.Host + "/" + id,
		"expires_at": time.Now().Add(ttl).UTC().Format(time.RFC3339),
	})
}

func handleServe(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !idRe.MatchString(id) {
		http.NotFound(w, r)
		return
	}

	matches, err := filepath.Glob(filepath.Join(uploadDir, id+".*"))
	if err != nil || len(matches) == 0 {
		http.NotFound(w, r)
		return
	}
	path := matches[0]

	info, err := os.Stat(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if time.Since(info.ModTime()) > ttl {
		os.Remove(path)
		http.NotFound(w, r)
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	http.ServeFile(w, r, path)
}

func cleanupLoop() {
	cleanup()
	t := time.NewTicker(10 * time.Minute)
	for range t.C {
		cleanup()
	}
}

func cleanup() {
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		log.Println("cleanup:", err)
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || e.IsDir() {
			continue
		}
		if time.Since(info.ModTime()) > ttl {
			if err := os.Remove(filepath.Join(uploadDir, e.Name())); err == nil {
				log.Println("deleted", e.Name())
			}
		}
	}
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
