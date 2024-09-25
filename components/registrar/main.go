package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Tenant struct represents a tenant in the system
type Tenant struct {
	TenantID  string `json:"tenantId"`
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type Worker struct {
	WorkerID string `json:"workerId"`
	Name     string `json:"name"`
	AIK      string `json:"AIK"`
}

// VerifySignatureRequest represents the input data for signature verification
type VerifySignatureRequest struct {
	Name      string `json:"name"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// In-memory synchronization and database reference
var (
	mtx sync.Mutex
	db  *sql.DB
)

var (
	red    *color.Color
	green  *color.Color
	yellow *color.Color
	blue   *color.Color
)

var registrarPORT string

func setRegistrarPort() {
	registrarPORT = os.Getenv("REGISTRAR_PORT")
	if registrarPORT == "" {
		registrarPORT = "8080"
		//log.Fatal("REGISTRAR_PORT is not set")
	}
	return
}

// Tenant functions
// ---------------------------------------------------------------------------------------------------------------------------

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
		return tenant, errors.New("Tenant not found")
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

// Utility function: Verify a signature using provided public key
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
func createTenant(c *gin.Context) {
	var req struct {
		Name      string `json:"name"`
		PublicKey string `json:"publicKey"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Lock access to prevent race conditions
	mtx.Lock()
	defer mtx.Unlock()

	// Check if tenant with the same name already exists
	nameExists, err := tenantExistsByName(req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check tenant by name", "status": "error"})
		return
	}
	if nameExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Tenant with the same name already exists", "status": "error"})
		return
	}

	// Check if the public key already exists
	pubKeyExists, err := tenantExistsByPublicKey(req.PublicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check tenant by public key", "status": "error"})
		return
	}
	if pubKeyExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Public key already exists", "status": "error"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create tenant", "status": "error"})
		return
	}

	// Send a successful response
	c.JSON(http.StatusCreated, gin.H{
		"message":  "Tenant created successfully",
		"tenantId": tenantID,
		"status":   "success",
	})
}

// Endpoint: Verify tenant's signature
func verifyTenantSignature(c *gin.Context) {
	var req VerifySignatureRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Get tenant public key from the database
	tenant, err := getTenantByName(req.Name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Tenant not found", "status": "error"})
		return
	}

	// Verify signature
	if err := verifySignature(tenant.PublicKey, req.Message, req.Signature); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Signature verification failed", "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Signature verification successful", "status": "success"})
}

// Endpoint: Get tenant by name (using GET method)
func getTenantIdByName(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Name parameter is required", "status": "error"})
		return
	}

	tenant, err := getTenantByName(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": err.Error(), "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tenantId": tenant.TenantID, "status": "success"})
}

// Worker functions
// ---------------------------------------------------------------------------------------------------------------------------------

// Utility function: Check if a worker already exists by name
func workerExistsByName(name string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM workers WHERE name = ?"
	err := db.QueryRow(query, name).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Utility function: Check if a public key already exists
func workerExistsByAIK(AIK string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM workers WHERE AIK = ?"
	err := db.QueryRow(query, AIK).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Utility function: Check if a worker already exists by Id
func workerExistsById(workerId string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM workers WHERE workerId = ?"
	err := db.QueryRow(query, workerId).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Insert a new tenant into the database
func insertWorker(worker Worker) error {
	query := "INSERT INTO workers (workerId, name, AIK) VALUES (?, ?, ?)"
	_, err := db.Exec(query, worker.WorkerID, worker.Name, worker.AIK)
	return err
}

// Fetch the tenant by name from the database
func getWorkerByName(name string) (Worker, error) {
	var worker Worker
	query := "SELECT workerId, name, AIK FROM workers WHERE name = ?"
	err := db.QueryRow(query, name).Scan(&worker.WorkerID, &worker.Name, &worker.AIK)
	if errors.Is(err, sql.ErrNoRows) {
		return worker, errors.New("Worker not found")
	} else if err != nil {
		return worker, err
	}
	return worker, nil
}

// Endpoint: Create a new worker (with name and AIK, generating UUID for WorkerID)
func createWorker(c *gin.Context) {
	var req struct {
		WorkerId string `json:"workerId"`
		Name     string `json:"name"`
		AIK      string `json:"AIK"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Lock access to prevent race conditions
	mtx.Lock()
	defer mtx.Unlock()

	// Check if worker with the same name already exists
	nameExists, err := workerExistsByName(req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check worker by name", "status": "error"})
		return
	}

	if nameExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Worker with the same name already exists", "status": "error"})
		return
	}

	// Check if worker with the same Id already exists
	idExists, err := workerExistsById(req.WorkerId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check worker by id", "status": "error"})
		return
	}

	if idExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Worker with the same UUID already exists", "status": "error"})
		return
	}

	// Check if the AIK already exists
	AIKExists, err := workerExistsByAIK(req.AIK)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check worker by AIK", "status": "error"})
		return
	}
	if AIKExists {
		c.JSON(http.StatusConflict, gin.H{"message": "AIK already exists", "status": "error"})
		return
	}

	// Create a new Worker object
	newWorker := Worker{
		WorkerID: req.WorkerId,
		Name:     req.Name,
		AIK:      req.AIK,
	}

	// Insert the new Worker into the database
	if err := insertWorker(newWorker); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create worker", "status": "error"})
		return
	}

	// Send a successful response
	c.JSON(http.StatusCreated, gin.H{
		"message":  "Worker created successfully",
		"workerId": newWorker.WorkerID,
		"status":   "success",
	})
}

// Endpoint: Verify Worker's signature using its registered AIK
func verifyWorkerSignature(c *gin.Context) {
	var req VerifySignatureRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Get tenant public key from the database
	worker, err := getWorkerByName(req.Name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Worker not found", "status": "error"})
		return
	}

	// Verify signature
	if err := verifySignature(worker.AIK, req.Message, req.Signature); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Signature verification failed", "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Signature verification successful", "status": "success"})
}

// Endpoint: Get worker by name (using GET method)
func getWorkerIdByName(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Name parameter is required", "status": "error"})
		return
	}

	worker, err := getWorkerByName(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": err.Error(), "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"workerId": worker.WorkerID, "status": "success"})
}

// remove a Worker from the database
func deleteWorker(workerName string) error {
	query := "DELETE FROM workers WHERE name = ?"
	_, err := db.Exec(query, workerName)
	return err
}

// deleteWorkerByName handles the deletion of a worker by its name
func deleteWorkerByName(c *gin.Context) {
	workerName := c.Query("name")
	if workerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "worker name is required"})
		return
	}

	// Lock access to prevent race conditions
	mtx.Lock()
	defer mtx.Unlock()

	// Call a function to delete the worker from your data store or Kubernetes
	err := deleteWorker(workerName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Worker deleted successfully"})
}

func main() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
	blue = color.New(color.FgBlue)

	setRegistrarPort()

	// Open database connection
	var err error
	db, err = sql.Open("sqlite", "./tenants.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create tenants table if it doesn't exist
	createTenantTableQuery := `
	CREATE TABLE IF NOT EXISTS tenants (
		tenantId TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		publicKey TEXT NOT NULL UNIQUE
	);`
	if _, err = db.Exec(createTenantTableQuery); err != nil {
		log.Fatal("Failed to create tenants table:", err)
	}

	// Create workers table if it doesn't exist
	createWorkerTableQuery := `
	CREATE TABLE IF NOT EXISTS workers (
		workerId TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		AIK TEXT NOT NULL UNIQUE
	);`
	if _, err = db.Exec(createWorkerTableQuery); err != nil {
		log.Fatal("Failed to create workers table:", err)
	}

	defer db.Close()

	// Initialize Gin router
	r := gin.Default()

	// Define routes for the Tenant API
	r.POST("/tenant/create", createTenant)          // POST create tenant
	r.POST("/tenant/verify", verifyTenantSignature) // POST verify tenant signature
	r.GET("/tenant/getIdByName", getTenantIdByName) // GET tenant ID by name

	r.POST("/worker/create", createWorker)               // POST create worker
	r.POST("/worker/verify", verifyWorkerSignature)      // POST verify worker signature
	r.GET("/worker/getIdByName", getWorkerIdByName)      // GET worker ID by name
	r.DELETE("/worker/deleteByName", deleteWorkerByName) // DELETE worker by Name

	// Start the server
	fmt.Printf(green.Sprintf("Registrar is running on port: %s\n", registrarPORT))
	err = r.Run(":" + registrarPORT)
	if err != nil {
		log.Fatal("Error while starting Registrar server")
	}
}
