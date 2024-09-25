package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"log"
	"net/http"
	"strings"
)

var (
	red    *color.Color
	green  *color.Color
	yellow *color.Color
)

var agentPORT string

// test purpose
var (
	privateAIK *rsa.PrivateKey
	privateEK  *rsa.PrivateKey
)

var workerId string

// Helper to verify environment variables
func verifyEnvVars() {
	if agentPORT == "" {
		agentPORT = "8083"
		//log.Fatal("One or more environment variables (REGISTRAR_HOST, REGISTRAR_PORT, POD_HANDLER_PORT) are not set")
	}
}

// Mock function to get AIK (Attestation Identity Key)
func getWorkerAIK() (*rsa.PublicKey, error) {
	// TPM interactions TODO - for now, generate a mock RSA key pair
	var err error
	privateAIK, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AIK: %v", err)
	}

	// Return the public key part of the generated AIK
	return &privateAIK.PublicKey, nil
}

// extract AIKDigest and ephemeral Key from received challenge
func extractChallengeElements(challenge string) (string, []byte, error) {
	var err error
	parts := strings.Split(challenge, "::")
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("malformed challenge: %v", err)
	}

	AIKDigest := parts[0]
	_, err = hex.DecodeString(AIKDigest)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode AIKDigest as hexadecimal: %v", err)
	}

	ephemeralKey, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode ephemeral Key: %v", err)
	}

	return AIKDigest, ephemeralKey, nil
}

// Mock function to get EK (Endorsement Key)
func getWorkerEK() (*rsa.PublicKey, error) {
	// TPM interactions TODO - for now, generate a mock RSA key pair
	var err error
	privateEK, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve EK: %v", err)
	}

	// Return the public key part of the generated EK
	return &privateEK.PublicKey, nil
}

// Helper function to encode the public key to PEM format (for printing)
func encodePublicKeyToPEM(pubKey *rsa.PublicKey) string {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY", // Use "PUBLIC KEY" for X.509 encoded keys
		Bytes: pubASN1,
	})
	return string(pubPEM)
}

func getWorkerIdentifyingData(c *gin.Context) {
	workerId = uuid.New().String()
	workerAIK, err := getWorkerAIK()

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": err.Error(), "status": "error"})
		return
	}

	workerEK, err := getWorkerEK()

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": err.Error(), "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"UUID": workerId, "EK": encodePublicKeyToPEM(workerEK), "AIK": encodePublicKeyToPEM(workerAIK)})
}

// Helper function to decrypt with mock private EK
func decryptWithEK(encryptedData []byte) ([]byte, error) {
	// Decrypt the challenge using the mock private EK
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateEK, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("EK decryption failed: %v", err)
	}
	return decryptedData, nil
}

// Helper function to calculate the AIK digest (mock)
func calculateAIKDigest(AIKPublicKey *rsa.PublicKey) (string, error) {
	// Calculate the digest of the mock AIK (using SHA-256 hash)
	AIKBytes, err := x509.MarshalPKIXPublicKey(AIKPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal AIK public key: %v", err)
	}
	hash := sha256.Sum256(AIKBytes)
	return fmt.Sprintf("%x", hash), nil
}

// Helper function to compute HMAC using the ephemeral key
func computeHMAC(message, key []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil), nil
}

func challengeWorkerEK(c *gin.Context) {
	// Define a struct to bind the incoming JSON request
	var req struct {
		WorkerChallenge string `json:"workerChallenge" binding:"required"`
	}

	// Bind the JSON request body to the struct
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request payload",
			"status":  "error",
		})
		return
	}

	// Decode the Base64-encoded challenge
	encryptedChallenge, err := base64.StdEncoding.DecodeString(req.WorkerChallenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid Base64 challenge",
			"status":  "error",
		})
		return
	}

	// Decrypt the challenge using the mock private EK
	decryptedData, err := decryptWithEK(encryptedChallenge)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Decryption failed",
			"status":  "error",
		})
		return
	}

	receivedAIKDigest, receivedEphemeralKey, err := extractChallengeElements(string(decryptedData))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Malformed challenge",
			"status":  "error",
		})
		return
	}

	// Calculate the mock AIK digest
	expectedAIKDigest, err := calculateAIKDigest(&privateAIK.PublicKey)
	if err != nil || receivedAIKDigest != expectedAIKDigest {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "AIK digest verification failed",
			"status":  "error",
		})
		return
	}

	// Compute HMAC on the worker UUID using the ephemeral key
	hmacValue, err := computeHMAC([]byte(workerId), receivedEphemeralKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "HMAC computation failed",
			"status":  "error",
		})
		return
	}

	// Respond with success, including the HMAC of the UUID
	c.JSON(http.StatusOK, gin.H{
		"message": "WorkerChallenge decrypted and verified successfully",
		"status":  "success",
		"HMAC":    base64.StdEncoding.EncodeToString(hmacValue),
	})
}

func main() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)

	verifyEnvVars()

	// Initialize Gin router
	r := gin.Default()

	// Define routes for the Tenant API
	r.GET("/agent/worker/identify", getWorkerIdentifyingData) // GET worker identifying data (newly generated UUID, AIK, EK)
	r.POST("/agent/worker/challenge", challengeWorkerEK)      // POST worker

	// Start the server
	fmt.Printf(green.Sprintf("Agent is running on port: %s\n", agentPORT))
	err := r.Run(":" + agentPORT)
	if err != nil {
		log.Fatal("Error while starting Registrar server")
	}
}
