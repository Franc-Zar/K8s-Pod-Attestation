package main

import (
	"crypto"
	"crypto/hmac"
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
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/simulator"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/uuid"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
)

type ImportBlobTransmitted struct {
	Duplicate     string `json:"duplicate"`
	EncryptedSeed string `json:"encrypted_seed"`
	PublicArea    string `json:"public_area"`
}

type AttestationRequest struct {
	Nonce     string `json:"nonce"`
	PodName   string `json:"podName"`
	PodUID    string `json:"podUID"`
	TenantId  string `json:"tenantId"`
	Signature string `json:"signature,omitempty"`
}

type Evidence struct {
	PodName     string `json:"podName"`
	PodUID      string `json:"podUID"`
	TenantId    string `json:"tenantId"`
	WorkerQuote string `json:"workerQuote"`
	WorkerIMA   string `json:"workerIMA"`
}

type AttestationResponse struct {
	Evidence  Evidence `json:"evidence"`
	Signature string   `json:"signature,omitempty"`
}

var (
	red                   *color.Color
	green                 *color.Color
	yellow                *color.Color
	agentPORT             string
	workerId              string
	TPMPath               string
	IMAMeasurementLogPath string
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
)

var (
	rwc       io.ReadWriteCloser
	AIKHandle tpmutil.Handle
)

func openTPM() {
	var err error

	if TPMPath == "simulator" {
		rwc, err = simulator.GetWithFixedSeedInsecure(1073741825)
		if err != nil {
			fmt.Printf(red.Sprintf("can't open TPM: %v\n", err))
			return
		}
	} else {
		rwc, err = tpmutil.OpenTPM(TPMPath)
		if err != nil {
			log.Fatalf("can't open TPM: %v\n", err)
			return
		}
	}
	return
}

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	agentPORT = getEnv("AGENT_PORT", "8083")
	TPMPath = getEnv("TPM_PATH", "simulator")
	IMAMeasurementLogPath = getEnv("IMA_PATH", "/root/ascii_runtime_measurements")
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
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

func getWorkerPublicAIK() (crypto.PublicKey, error) {
	if AIKHandle.HandleValue() == 0 {
		return nil, fmt.Errorf("AIK is not already created")
	}

	retrievedAK, err := client.NewCachedKey(rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), AIKHandle)
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve AIK from TPM")
	}
	return retrievedAK.PublicKey(), nil
}

// Mock function to get EK (Endorsement Key)
func getWorkerEKandCertificate() (crypto.PublicKey, string, error) {
	EK, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR: could not get EndorsementKeyRSA: %v", err)
	}
	defer EK.Close()
	var pemEKCert []byte

	EKCert := EK.Cert()
	if EKCert != nil {
		pemEKCert = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: EKCert.Raw,
		})
	}

	if pemEKCert == nil {
		pemEKCert = []byte("EK Certificate not provided")
	}

	pemPublicEK := encodePublicKeyToPEM(EK.PublicKey())

	return pemPublicEK, string(pemEKCert), nil
}

// Function to create a new AIK (Attestation Identity Key) for the Agent
func createWorkerAIK() (crypto.PublicKey, error) {
	AIK, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR: could not get AttestationKeyRSA: %v", err)
	}
	defer AIK.Close()

	// used to later retrieve newly created AIK inside the TPM
	AIKHandle = AIK.Handle()

	pemPublicAIK := encodePublicKeyToPEM(AIK.PublicKey())

	// Return the public key part of the generated AIK
	return pemPublicAIK, nil
}

// extract AIKDigest and ephemeral Key from received challenge
func extractChallengeElements(challenge string) (string, []byte, []byte, error) {
	var err error
	challengeElements := strings.Split(challenge, "::")
	if len(challengeElements) != 3 {
		return "", nil, nil, fmt.Errorf("malformed challenge: %v", err)
	}

	AIKDigest := challengeElements[0]
	_, err = hex.DecodeString(AIKDigest)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to decode AIKDigest as hexadecimal: %v", err)
	}

	ephemeralKey, err := base64.StdEncoding.DecodeString(challengeElements[1])
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to decode ephemeral Key: %v", err)
	}

	nonce, err := hex.DecodeString(challengeElements[2])
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to decode nonce: %v", err)
	}
	return AIKDigest, ephemeralKey, nonce, nil
}

// Helper function to encode the public key to PEM format (for printing)
func encodePublicKeyToPEM(pubKey crypto.PublicKey) string {
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

	// TODO send ek certificate to be validated _
	workerEK, EKCert, err := getWorkerEKandCertificate()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": err.Error(), "status": "error"})
		return
	}

	workerAIK, err := createWorkerAIK()

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": err.Error(), "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"UUID": workerId, "EK": workerEK, "EKCert": EKCert, "AIK": workerAIK})
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
func signWithAIK(message string) (string, error) {
	if AIKHandle.HandleValue() == 0 {
		return "", fmt.Errorf("AIK is not already created")
	}

	AIK, err := client.NewCachedKey(rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), AIKHandle)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve AIK from TPM")
	}

	defer AIK.Close()

	AIKSignedData, err := AIK.SignData([]byte(message))
	if err != nil {
		return "", fmt.Errorf("Failed to sign with AIK")
	}
	return base64.StdEncoding.EncodeToString(AIKSignedData), nil
}

func decryptWithEK(encryptedData string) ([]byte, error) {
	decodedChallenge, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("error decoding challenge")
	}

	var importBlobTransmitted ImportBlobTransmitted
	err = json.Unmarshal(decodedChallenge, &importBlobTransmitted)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling challenge: %v", err)
	}

	// Base64 decode the received data
	duplicate, err := base64.StdEncoding.DecodeString(importBlobTransmitted.Duplicate)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 data: %v", err)
	}

	encryptedSeed, err := base64.StdEncoding.DecodeString(importBlobTransmitted.EncryptedSeed)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 data: %v", err)
	}

	publicArea, err := base64.StdEncoding.DecodeString(importBlobTransmitted.PublicArea)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 data: %v", err)
	}

	blob := &pb.ImportBlob{
		Duplicate:     duplicate,
		EncryptedSeed: encryptedSeed,
		PublicArea:    publicArea,
		Pcrs:          nil,
	}

	// Retrieve the TPM's endorsement key (EK)
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		return nil, fmt.Errorf("ERROR: could not get EndorsementKeyRSA: %v", err)
	}
	defer ek.Close()

	// Decrypt the ImportBlob using the TPM EK
	output, err := ek.Import(blob)
	if err != nil {
		return nil, fmt.Errorf("failed to import blob: %v", err)
	}

	return output, nil
}

// Helper function to calculate the AIK digest (mock)
func computeAIKDigest(AIKPublicKey crypto.PublicKey) (string, error) {
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
			"message": "Attestation Request Signature verification failed",
			"status":  "error",
		})
		return
	}

	nonceBytes, err := hex.DecodeString(attestationRequest.Nonce)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Failed to decode nonce",
			"status":  "error",
		})
		return
	}

	PCRsToQuote := []int{10}
	workerQuoteJSON, err := quoteGeneralPurposePCRs(nonceBytes, PCRsToQuote)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": err.Error(),
			"status":  "error",
		})
		return
	}

	workerIMA, err := getWorkerIMAMeasurementLog()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": err.Error(),
			"status":  "error",
		})
		return
	}

	// TODO collect claims and generate Evidence
	evidence := Evidence{
		PodName:     attestationRequest.PodName,
		PodUID:      attestationRequest.PodUID,
		TenantId:    attestationRequest.TenantId,
		WorkerQuote: workerQuoteJSON,
		WorkerIMA:   workerIMA,
	}

	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to serialize Evidence",
			"status":  "error",
		})
		return
	}

	signedEvidence, err := signWithAIK(string(evidenceJSON))
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

func getWorkerIMAMeasurementLog() (string, error) {
	// Open the file
	IMAMeasurementLog, err := os.Open(IMAMeasurementLogPath)
	if err != nil {
		return "", fmt.Errorf("failed to open IMA measurement log: %v", err)
	}
	defer IMAMeasurementLog.Close()

	// Read the file content
	fileContent, err := io.ReadAll(IMAMeasurementLog)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	// Encode the file content into Base64
	base64Encoded := base64.StdEncoding.EncodeToString(fileContent)

	return base64Encoded, nil
}

// Custom function that checks if PCRstoQuote contains any element from bootReservedPCRs
// and returns the boolean and the list of matching PCRs
func containsAndReturnPCR(PCRstoQuote []int, bootReservedPCRs []int) (bool, []int) {
	var foundPCRs []int
	for _, pcr := range PCRstoQuote {
		if slices.Contains(bootReservedPCRs, pcr) {
			foundPCRs = append(foundPCRs, pcr)
		}
	}
	if len(foundPCRs) == 0 {
		return false, nil // No matching PCRs found
	}
	return true, foundPCRs
}

func quoteGeneralPurposePCRs(nonce []byte, PCRsToQuote []int) (string, error) {
	bootReservedPCRs := []int{0, 1, 2, 3, 4, 5, 6, 7}
	// Custom function to return both found status and the PCR value
	PCRsContainsBootReserved, foundPCR := containsAndReturnPCR(PCRsToQuote, bootReservedPCRs)
	if PCRsContainsBootReserved {
		return "", fmt.Errorf("Cannot compute quote on provided PCR set %v: boot reserved PCRs where included %v", foundPCR, bootReservedPCRs)
	}

	generalPurposePCRs := tpm2legacy.PCRSelection{
		Hash: tpm2legacy.AlgSHA256,
		PCRs: PCRsToQuote,
	}

	AIK, err := client.NewCachedKey(rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), AIKHandle)
	if err != nil {
		return "", fmt.Errorf("Error while retrieving AIK: %v", err)
	}

	quote, err := AIK.Quote(generalPurposePCRs, nonce)
	if err != nil {
		return "", fmt.Errorf("failed to create quote over PCRs %v: %v", PCRsToQuote, err)
	}
	quoteJSON, err := json.Marshal(quote)
	if err != nil {
		return "", fmt.Errorf("Failed to parse quote result as json: %v", err)
	}
	return string(quoteJSON), nil
}

func quoteBootAggregate(nonce []byte) (string, error) {
	bootReservedPCRs := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	bootPCRs := tpm2legacy.PCRSelection{
		Hash: tpm2legacy.AlgSHA256,
		PCRs: bootReservedPCRs,
	}

	AIK, err := client.NewCachedKey(rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), AIKHandle)
	if err != nil {
		return "", fmt.Errorf("Error while retrieving AIK: %v", err)
	}

	quote, err := AIK.Quote(bootPCRs, nonce)
	if err != nil {
		return "", fmt.Errorf("failed to create quote over PCRs 0-7: %v", err)
	}
	quoteJSON, err := json.Marshal(quote)
	if err != nil {
		return "", fmt.Errorf("Failed to parse quote result as json: %v", err)
	}
	return string(quoteJSON), nil
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

	// Decrypt the challenge using the mock private EK
	decryptedData, err := decryptWithEK(req.WorkerChallenge)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Decryption failed",
			"status":  "error",
		})
		return
	}

	receivedAIKDigest, receivedEphemeralKey, nonce, err := extractChallengeElements(string(decryptedData))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Malformed challenge",
			"status":  "error",
		})
		return
	}

	retrievedAIKPublicKey, err := getWorkerPublicAIK()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "Error while retrieving Agent AIK",
			"status":  "error",
		})
		return
	}

	// Calculate the mock AIK digest
	expectedAIKDigest, err := computeAIKDigest(retrievedAIKPublicKey)
	if err != nil || receivedAIKDigest != expectedAIKDigest {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "AIK digest verification failed",
			"status":  "error",
		})
		return
	}

	bootQuoteJSON, err := quoteBootAggregate(nonce)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error while computing Boot Aggregate quote",
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
		"message":         "WorkerChallenge decrypted and verified successfully",
		"status":          "success",
		"HMAC":            base64.StdEncoding.EncodeToString(hmacValue),
		"workerBootQuote": bootQuoteJSON,
	})
	return
}

func main() {
	initializeColors()
	loadEnvironmentVariables()
	openTPM()

	defer func() {
		err := rwc.Close()
		if err != nil {
			fmt.Printf(red.Sprintf("can't close TPM: %v\n", err))
			return
		}
	}()

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
		log.Fatal("Error while starting Agent server")
	}
}
