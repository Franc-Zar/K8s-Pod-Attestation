package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// Tenant struct represents a tenant in the system
type Tenant struct {
	TenantID  string `json:"tenantId"`
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

// VerifySignatureRequest represents the input data for signature verification
type VerifySignatureRequest struct {
	Name      string `json:"name"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// In-memory synchronization and database reference
var (
	mu sync.Mutex
	db *sql.DB
)

// Utility function: Check if a tenant already exists by name
func tenantExistsByName(name string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM tenants WHERE name = ?"
	err := db.QueryRow(query, name).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Utility function: Check if a public key already exists
func tenantExistsByPublicKey(publicKey string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM tenants WHERE publicKey = ?"
	err := db.QueryRow(query, publicKey).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Fetch the tenant by name from the database
func getTenantByName(name string) (Tenant, error) {
	var tenant Tenant
	query := "SELECT tenantId, name, publicKey FROM tenants WHERE name = ?"
	err := db.QueryRow(query, name).Scan(&tenant.TenantID, &tenant.Name, &tenant.PublicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return tenant, errors.New("tenant not found")
	} else if err != nil {
		return tenant, err
	}
	return tenant, nil
}

// Insert a new tenant into the database
func insertTenant(tenant Tenant) error {
	query := "INSERT INTO tenants (tenantId, name, publicKey) VALUES (?, ?, ?)"
	_, err := db.Exec(query, tenant.TenantID, tenant.Name, tenant.PublicKey)
	return err
}

// Utility function: Verify a signature using tenant's public key
func verifySignature(publicKeyPEM string, message, signature string) error {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return errors.New("failed to decode PEM block containing public key")
	}

	rsaPubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse PKCS1 public key: %v", err)
	}

	hashed := sha256.Sum256([]byte(message))
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], sigBytes)
	return err
}

// Endpoint: Create a new tenant (with name and public key, generating UUID for TenantID)
func createTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		PublicKey string `json:"publicKey"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Lock access to prevent race conditions
	mu.Lock()
	defer mu.Unlock()

	// Check if tenant with the same name already exists
	nameExists, err := tenantExistsByName(req.Name)
	if err != nil {
		http.Error(w, "Failed to check tenant by name", http.StatusInternalServerError)
		return
	}
	if nameExists {
		http.Error(w, "Tenant with the same name already exists", http.StatusConflict)
		return
	}

	// Check if the public key already exists
	pubKeyExists, err := tenantExistsByPublicKey(req.PublicKey)
	if err != nil {
		http.Error(w, "Failed to check tenant by public key", http.StatusInternalServerError)
		return
	}
	if pubKeyExists {
		http.Error(w, "Public key already exists", http.StatusConflict)
		return
	}

	// Generate a new UUID for the tenant
	tenantID := uuid.New().String()

	// Create a new tenant object
	newTenant := Tenant{
		TenantID:  tenantID,
		Name:      req.Name,
		PublicKey: req.PublicKey,
	}

	// Insert the new tenant into the database
	if err := insertTenant(newTenant); err != nil {
		http.Error(w, "Failed to create tenant", http.StatusInternalServerError)
		return
	}

	// Send a successful response
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "Tenant created successfully",
		"tenantId": tenantID,
	})
}

// Endpoint: Verify tenant's signature
func verifyTenantSignature(w http.ResponseWriter, r *http.Request) {
	var req VerifySignatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Get tenant public key from the database
	tenant, err := getTenantByName(req.Name)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	// Verify signature
	if err := verifySignature(tenant.PublicKey, req.Message, req.Signature); err != nil {
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Signature verification successful")
}

// Endpoint: Get tenant by name (using GET method)
func getTenantIDByName(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "Name parameter is required", http.StatusBadRequest)
		return
	}

	tenant, err := getTenantByName(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"tenantId": tenant.TenantID})
}

func main() {
	// Open database connection (assuming SQLite for simplicity)
	var err error
	db, err = sql.Open("sqlite3", "./tenants.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create tenants table if it doesn't exist
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS tenants (
		tenantId TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		publicKey TEXT NOT NULL UNIQUE
	);`
	if _, err = db.Exec(createTableQuery); err != nil {
		log.Fatal("Failed to create tenants table:", err)
	}

	defer db.Close()

	// Define routes for the Tenant API
	http.HandleFunc("/tenant/create", createTenant)          // POST create tenant
	http.HandleFunc("/tenant/verify", verifyTenantSignature) // POST verify signature
	http.HandleFunc("/tenant/getByName", getTenantIDByName)  // GET get tenant by name

	// Start the server
	fmt.Println("Server is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
