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
	"github.com/google/go-tpm-tools/simulator"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/uuid"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"sync"
)

type RegistrationAcknowledge struct {
	Message           string `json:"message"`
	Status            string `json:"status"`
	VerifierPublicKey string `json:"verifierPublicKey"`
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

type WorkerChallenge struct {
	AIKCredential      string `json:"AIKCredential"`
	AIKEncryptedSecret string `json:"AIKEncryptedSecret"`
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
	EKHandle  tpmutil.Handle
	TPMmtx    sync.Mutex
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
	agentPORT = getEnv("AGENT_PORT", "8080")
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

// Mock function to get EK (Endorsement Key)
func getWorkerEKandCertificate() (crypto.PublicKey, string) {
	TPMmtx.Lock()
	defer TPMmtx.Unlock()

	EK, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR: could not get EndorsementKeyRSA: %v", err)
	}

	EKHandle = EK.Handle()

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

	return pemPublicEK, string(pemEKCert)
}

// Function to create a new AIK (Attestation Identity Key) for the Agent
func createWorkerAIK() (string, string) {
	TPMmtx.Lock()
	defer TPMmtx.Unlock()

	AIK, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR: could not get AttestationKeyRSA: %v", err)
	}
	defer AIK.Close()

	// used to later retrieve newly created AIK inside the TPM
	AIKHandle = AIK.Handle()

	AIKNameData, err := AIK.Name().Encode()
	if err != nil {
		log.Fatalf("failed to encode AIK Name data")
	}

	AIKPublicArea, err := AIK.PublicArea().Encode()
	if err != nil {
		log.Fatalf("failed to encode AIK public area")
	}

	encodedNameData := base64.StdEncoding.EncodeToString(AIKNameData)
	encodedPublicArea := base64.StdEncoding.EncodeToString(AIKPublicArea)

	// Return AIK material
	return encodedNameData, encodedPublicArea
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

	workerEK, EKCert := getWorkerEKandCertificate()
	workerAIKNameData, workerAIKPublicArea := createWorkerAIK()

	c.JSON(http.StatusOK, gin.H{"UUID": workerId, "EK": workerEK, "EKCert": EKCert, "AIKNameData": workerAIKNameData, "AIKPublicArea": workerAIKPublicArea})
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
func signWithAIK(message []byte) (string, error) {
	TPMmtx.Lock()
	defer TPMmtx.Unlock()

	if AIKHandle.HandleValue() == 0 {
		return "", fmt.Errorf("AIK is not already created")
	}

	AIK, err := client.NewCachedKey(rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), AIKHandle)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve AIK from TPM")
	}

	defer AIK.Close()

	AIKSignedData, err := AIK.SignData(message)
	if err != nil {
		return "", fmt.Errorf("Failed to sign with AIK: %v", err)
	}
	return base64.StdEncoding.EncodeToString(AIKSignedData), nil
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
	workerQuote, err := quoteGeneralPurposePCRs(nonceBytes, PCRsToQuote)
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
		WorkerQuote: workerQuote,
		WorkerIMA:   workerIMA,
	}

	evidenceDigest, err := computeEvidenceDigest(evidence)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to compute Evidence digest: " + err.Error(),
			"status":  "error",
		})
		return
	}

	signedEvidence, err := signWithAIK(evidenceDigest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to sign Evidence: " + err.Error(),
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

// Function to compute the SHA256 digest of the Evidence structure
func computeEvidenceDigest(evidence Evidence) ([]byte, error) {
	// Serialize Evidence struct to JSON
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize evidence: %v", err)
	}

	// Compute SHA256 hash
	hash := sha256.New()
	_, err = hash.Write(evidenceJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash: %v", err)
	}

	// Get the final hash as a hex-encoded string
	digest := hash.Sum(nil)
	return digest, nil
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
	TPMmtx.Lock()
	defer TPMmtx.Unlock()

	bootReservedPCRs := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
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
	TPMmtx.Lock()
	defer TPMmtx.Unlock()

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
		return "", fmt.Errorf("failed to create quote over PCRs 0-9: %v", err)
	}
	quoteJSON, err := json.Marshal(quote)
	if err != nil {
		return "", fmt.Errorf("Failed to parse quote result as json: %v", err)
	}
	return string(quoteJSON), nil
}

func activateAIKCredential(AIKCredential, AIKEncryptedSecret string) ([]byte, error) {
	TPMmtx.Lock()
	defer TPMmtx.Unlock()
	decodedCredential, err := base64.StdEncoding.DecodeString(AIKCredential)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode AIK Credential")
	}
	decodedSecret, err := base64.StdEncoding.DecodeString(AIKEncryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode AIK encrypted Secret")
	}

	// Initiate a session for PolicySecret, specific for endorsement
	session, _, err := tpm2legacy.StartAuthSession(
		rwc,
		tpm2legacy.HandleNull,
		tpm2legacy.HandleNull,
		make([]byte, 16),
		nil,
		tpm2legacy.SessionPolicy,
		tpm2legacy.AlgNull,
		tpm2legacy.AlgSHA256,
	)
	if err != nil {
		return nil, fmt.Errorf("creating auth session failed: %v", err)
	}

	// Set PolicySecret on the endorsement handle, enabling EK use
	auth := tpm2legacy.AuthCommand{Session: tpm2legacy.HandlePasswordSession, Attributes: tpm2legacy.AttrContinueSession}
	if _, _, err := tpm2legacy.PolicySecret(rwc, tpm2legacy.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		return nil, fmt.Errorf("policy secret failed: %v", err)
	}

	// Create authorization commands, linking session and password auth
	auths := []tpm2legacy.AuthCommand{
		{Session: tpm2legacy.HandlePasswordSession, Attributes: tpm2legacy.AttrContinueSession},
		{Session: session, Attributes: tpm2legacy.AttrContinueSession},
	}

	// Attempt to activate the credential
	challengeSecret, err := tpm2legacy.ActivateCredentialUsingAuth(rwc, auths, AIKHandle, EKHandle, decodedCredential[2:], decodedSecret[2:])
	if err != nil {
		return nil, fmt.Errorf("AIK activate_credential failed: %v", err)
	}

	return challengeSecret, nil
}

func challengeWorkerEK(c *gin.Context) {
	var workerChallenge WorkerChallenge
	// Bind the JSON request body to the struct
	if err := c.BindJSON(&workerChallenge); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request payload",
			"status":  "error",
		})
		return
	}

	challengeSecret, err := activateAIKCredential(workerChallenge.AIKCredential, workerChallenge.AIKEncryptedSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Agent failed to perform Credential Activation",
			"status":  "error",
		})
		return
	}
	ephemeralKey := challengeSecret
	quoteNonce := challengeSecret[:8]

	bootQuoteJSON, err := quoteBootAggregate(quoteNonce)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error while computing Boot Aggregate quote",
			"status":  "error",
		})
		return
	}

	// Compute HMAC on the worker UUID using the ephemeral key
	hmacValue, err := computeHMAC([]byte(workerId), ephemeralKey)
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

func acknowledgeRegistration(c *gin.Context) {
	var acknowledge RegistrationAcknowledge
	// Bind the JSON request body to the struct
	if err := c.BindJSON(&acknowledge); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request payload",
			"status":  "error",
		})
		return
	}

	if acknowledge.Status == "success" {
		verifierPublicKey = acknowledge.VerifierPublicKey
		c.JSON(http.StatusCreated, gin.H{
			"message": "Agent acknowledged success of registration and obtained Verifier Public Key",
			"status":  "success",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Agent acknowledged failure of registration",
		"status":  "error",
	})
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
	r.GET("/agent/worker/registration/identify", getWorkerIdentifyingData) // GET worker identifying data (newly generated UUID, AIK, EK)
	r.POST("/agent/worker/registration/challenge", challengeWorkerEK)      // POST challenge worker for Registration
	r.POST("/agent/worker/registration/acknowledge", acknowledgeRegistration)

	r.POST("/agent/pod/attest", podAttestation) // POST attestation against one Pod running upon Worker of this agent
	// Start the server
	fmt.Printf(green.Sprintf("Agent is running on port: %s\n", agentPORT))
	err := r.Run(":" + agentPORT)
	if err != nil {
		log.Fatal("Error while starting Agent server")
	}
}
