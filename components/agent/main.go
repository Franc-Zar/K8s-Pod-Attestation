package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type AttestationRequest struct {
	Nonce     string `json:"nonce"`
	PodName   string `json:"podName"`
	PodUID    string `json:"podUID"`
	TenantId  string `json:"tenantId"`
	Signature string `json:"signature,omitempty"`
}

type Evidence struct {
	Nonce    string `json:"nonce"`
	PodName  string `json:"podName"`
	PodUID   string `json:"podUID"`
	TenantId string `json:"tenantId"`
}

type AttestationResponse struct {
	Evidence  Evidence `json:"evidence"`
	Signature string   `json:"signature,omitempty"`
}

var (
	red       *color.Color
	green     *color.Color
	yellow    *color.Color
	agentPORT string
	workerId  string
)

// TEST PURPOSE
var (
	verifierPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoi/38EDObItiLd1Q8Cy
XsPaHjOreYqVJYEO4NfCZR2H01LXrdj/LcpyrB1rKBc4UWI8lroSdhjMJxC62372
WvDk9cD5k+iyPwdM+EggpiRfEmHWF3zob8junyWHW6JInf0+AGhbKgBfMXo9PvAn
r5CVeqp2BrstdZtrWVRuQAKip9c7hl+mHODkE5yb0InHyRe5WWr5P7wtXtAPM6SO
8dVk/QWXdsB9rsb+Ejy4LHSIUpHUOZO8LvGD1rVLO82H4EUXKBFeiOEJjly4HOkv
mFe/c/Cma1pM+702X6ULf0/BIMJkWzD3INdLtk8FE8rIxrrMSnDtmWw9BgGdsDgk
pQIDAQAB
-----END PUBLIC KEY-----`
	privateAIK *rsa.PrivateKey
	privateEK  *rsa.PrivateKey
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	agentPORT = getEnv("AGENT_PORT", "8083")
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		if key == "ATTESTATION_NAMESPACE" {
			fmt.Printf(yellow.Sprintf("[%s] '%s' environment variable missing: setting default value\n", time.Now().Format("02-01-2006 15:04:05"), key))
		}
		return defaultValue
	}
	return value
}

// initializeColors sets up color variables for console output.
func initializeColors() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
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

// Utility function: Verify a signature using provided public key
func decodePublicKeyFromPEM(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	var rsaPubKey *rsa.PublicKey
	var err error

	switch block.Type {
	case "RSA PUBLIC KEY":
		rsaPubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 public key: %v", err)
		}
	case "PUBLIC KEY":
		parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %v", err)
		}
		var ok bool
		rsaPubKey, ok = parsedKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
	}

	return rsaPubKey, nil
}

// Utility function: Verify a signature using provided public key
func verifySignature(publicKeyPEM string, message string, signature string) error {
	rsaPubKey, err := decodePublicKeyFromPEM(publicKeyPEM)

	hashed := sha256.Sum256([]byte(message))
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], sigBytes)
	return err
}

// Utility function: Sign a message using the provided private key
func signMessage(rsaPrivateKey *rsa.PrivateKey, message string) (string, error) {
	// Hash the message using SHA256
	hashed := sha256.Sum256([]byte(message))

	// Sign the hashed message using the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Encode the signature in Base64 and return it
	return base64.StdEncoding.EncodeToString(signature), nil
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

func podAttestation(c *gin.Context) {
	var attestationRequest AttestationRequest

	// Bind the JSON request body to the struct
	if err := c.BindJSON(&attestationRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request payload",
			"status":  "error",
		})
		return
	}

	receivedAttestationRequest := AttestationRequest{
		Nonce:    attestationRequest.Nonce,
		PodName:  attestationRequest.PodName,
		PodUID:   attestationRequest.PodUID,
		TenantId: attestationRequest.TenantId,
	}

	receivedAttestationRequestJSON, err := json.Marshal(receivedAttestationRequest)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error serializing Attestation Request",
			"status":  "error",
		})
		return
	}

	err = verifySignature(verifierPublicKey, string(receivedAttestationRequestJSON), attestationRequest.Signature)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": err.Error(),
			"status":  "error",
		})
		return
	}

	// TODO collect claims and generate Evidence
	evidence := Evidence{
		Nonce:    attestationRequest.Nonce,
		PodName:  attestationRequest.PodName,
		PodUID:   attestationRequest.PodUID,
		TenantId: attestationRequest.TenantId,
	}

	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to serialize Evidence",
			"status":  "error",
		})
		return
	}

	signedEvidence, err := signMessage(privateAIK, string(evidenceJSON))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to sign Evidence",
			"status":  "error",
		})
		return
	}

	attestationResponse := AttestationResponse{
		Evidence:  evidence,
		Signature: signedEvidence,
	}

	c.JSON(http.StatusOK, gin.H{
		"attestationResponse": attestationResponse,
		"message":             "Attestation Request successfully processed",
		"status":              "success",
	})
	return
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
	initializeColors()
	loadEnvironmentVariables()

	// Initialize Gin router
	r := gin.Default()

	// Define routes for the Tenant API
	r.GET("/agent/worker/identify", getWorkerIdentifyingData) // GET worker identifying data (newly generated UUID, AIK, EK)
	r.POST("/agent/worker/challenge", challengeWorkerEK)      // POST challenge worker for Registration
	r.POST("/agent/pod/attest", podAttestation)               // POST attestation against one Pod running upon Worker of this agent

	// Start the server
	fmt.Printf(green.Sprintf("Agent is running on port: %s\n", agentPORT))
	err := r.Run(":" + agentPORT)
	if err != nil {
		log.Fatal("Error while starting Registrar server")
	}
}
