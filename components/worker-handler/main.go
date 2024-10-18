package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/fatih/color"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"io"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/homedir"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Struct definitions
type WorkerNode struct {
	WorkerId string `json:"WorkerId"`
	Name     string `json:"name"`
	AIK      string `json:"AIK"`
}

type WorkerResponse struct {
	UUID   string `json:"UUID"`
	EK     string `json:"EK"`
	EKCert string `json:"EKCert"`
	AIK    string `json:"AIK"`
}

type NewWorkerResponse struct {
	Message  string `json:"message"`
	WorkerId string `json:"workerId"`
	Status   string `json:"status"`
}

type WorkerChallenge struct {
	WorkerChallenge string `json:"workerChallenge"`
}

type WorkerChallengeResponse struct {
	Message         string `json:"message"`
	Status          string `json:"status"`
	HMAC            string `json:"HMAC"`
	WorkerBootQuote string `json:"workerBootQuote"`
}

type ImportBlobTransmitted struct {
	Duplicate     string `json:"duplicate"`
	EncryptedSeed string `json:"encrypted_seed"`
	PublicArea    string `json:"public_area"`
}

type InputQuote struct {
	Quote  string `json:"quote"`
	RawSig string `json:"raw_sig"`
	PCRs   PCRSet `json:"pcrs"`
}

// PCRSet represents the PCR values and the hash algorithm used
type PCRSet struct {
	Hash int               `json:"hash"`
	PCRs map[string]string `json:"pcrs"`
}

type WorkerWhitelistCheckRequest struct {
	OsName        string `json:"osName"`
	BootAggregate string `json:"bootAggregate"`
	HashAlg       string `json:"hashAlg"`
}

// Color variables for output
var (
	red                  *color.Color
	green                *color.Color
	yellow               *color.Color
	clientset            *kubernetes.Clientset
	dynamicClient        dynamic.Interface
	attestationNamespace string
	registrarPORT        string
	registrarHOST        string
	agentHOST            string
	agentPORT            string
	whitelistHOST        string
	whitelistPORT        string
)

// initializeColors sets up color variables for console output.
func initializeColors() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
}

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	registrarHOST = getEnv("REGISTRAR_HOST", "localhost")
	registrarPORT = getEnv("REGISTRAR_PORT", "8080")
	attestationNamespace = getEnv("ATTESTATION_NAMESPACE", "default")
	agentHOST = getEnv("AGENT_HOST", "10.0.2.13")
	agentPORT = getEnv("AGENT_PORT", "30000")
	whitelistHOST = getEnv("WHITELIST_HOST", "localhost")
	whitelistPORT = getEnv("WHITELIST_PORT", "9090")
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// Helper function to verify HMAC
func verifyHMAC(message, ephemeralKey, providedHMAC []byte) error {
	h := hmac.New(sha256.New, ephemeralKey)
	h.Write(message)
	expectedHMAC := h.Sum(nil)

	if !hmac.Equal(expectedHMAC, providedHMAC) {
		return fmt.Errorf("HMAC verification failed")
	}

	return nil
}

// Encrypts data with the provided public key derived from the ephemeral key (EK)
func encryptWithEK(publicEK *rsa.PublicKey, plaintext []byte) (string, error) {
	// Create the ImportBlob using the public EK
	importBlob, err := server.CreateImportBlob(publicEK, plaintext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt challenge")
	}

	importBlobToSend := ImportBlobTransmitted{
		Duplicate:     base64.StdEncoding.EncodeToString(importBlob.Duplicate),
		EncryptedSeed: base64.StdEncoding.EncodeToString(importBlob.EncryptedSeed),
		PublicArea:    base64.StdEncoding.EncodeToString(importBlob.PublicArea),
	}

	importBlobToSendJSON, err := json.Marshal(importBlobToSend)
	if err != nil {
		return "", fmt.Errorf("failed to marshal encrypted challenge")
	}

	return base64.StdEncoding.EncodeToString(importBlobToSendJSON), nil
}

// configureKubernetesClient initializes the Kubernetes client.
func configureKubernetesClient() {
	var err error
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			panic(err)
		}
	}
	dynamicClient = dynamic.NewForConfigOrDie(config)
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}
}

// Watch for node events
func watchNodes() {
	watcher, err := clientset.CoreV1().Nodes().Watch(context.Background(), v1.ListOptions{})
	if err != nil {
		panic(err)
	}
	defer watcher.Stop()

	for {
		select {
		case event := <-watcher.ResultChan():
			node, ok := event.Object.(*corev1.Node)
			if !ok {
				continue
			}
			handleNodeEvent(event, node)
		}
	}
}

func nodeIsRegistered(nodeName string) bool {
	registrarSearchWorkerURL := fmt.Sprintf("http://%s:%s/worker/getIdByName?name=%s", registrarHOST, registrarPORT, nodeName)

	resp, err := http.Get(registrarSearchWorkerURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	return true
}

// deleteNode deletes the node from the Kubernetes cluster.
func deleteNodeFromCluster(nodeName string) error {
	err := clientset.CoreV1().Nodes().Delete(context.TODO(), nodeName, v1.DeleteOptions{})
	return err
}

// Handle events for nodes
func handleNodeEvent(event watch.Event, node *corev1.Node) {
	switch event.Type {
	case watch.Added:
		if !nodeIsControlPlane(node) && !nodeIsRegistered(node.Name) {
			fmt.Printf(green.Sprintf("[%s] Worker node %s joined the cluster\n", time.Now().Format("02-01-2006 15:04:05"), node.Name))
			if !workerRegistration(node) {
				if deleteNodeFromCluster(node.Name) != nil {
					fmt.Printf(red.Sprintf("[%s] Failed to delete Worker node %s the cluster\n", time.Now().Format("02-01-2006 15:04:05"), node.Name))
				}
			}
		}

	case watch.Deleted:
		if !nodeIsControlPlane(node) {
			fmt.Printf(yellow.Sprintf("[%s] Worker node %s deleted from the cluster\n", time.Now().Format("02-01-2006 15:04:05"), node.Name))
			workerRemoval(node)
		}
	}
}

// Check if Node being considered is Control Plane
func nodeIsControlPlane(node *corev1.Node) bool {
	_, exists := node.Labels["node-role.kubernetes.io/control-plane"]
	return exists
}

// Calculate the AIK digest (mock)
func calculateAIKDigest(AIKPublicKey *rsa.PublicKey) (string, error) {
	AIKBytes, err := x509.MarshalPKIXPublicKey(AIKPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal AIK public key: %v", err)
	}
	hash := sha256.Sum256(AIKBytes)
	return fmt.Sprintf("%x", hash), nil
}

func decodePublicKeyFromPEM(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
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
			return nil, errors.New("not an RSA public key")
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
	}

	return rsaPubKey, nil
}

// Generate a cryptographically secure random symmetric key of the specified size in bytes
func generateEphemeralKey(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("key size must be greater than 0")
	}

	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}
	return key, nil
}

func workerRemoval(node *corev1.Node) {
	registrarWorkerDeletionURL := fmt.Sprintf("http://%s:%s/worker/deleteByName?name=%s", registrarHOST, registrarPORT, node.GetName())

	// Create a new HTTP request
	req, err := http.NewRequest(http.MethodDelete, registrarWorkerDeletionURL, nil)
	if err != nil {
		fmt.Printf(red.Sprintf("Error creating Worker removal request: %v\n", err))
		return
	}

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf(red.Sprintf("Error sending Worker removal request: %v\n", err))
		return
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		fmt.Printf(red.Sprintf("Failed to delete Worker: received status code %d\n", resp.StatusCode))
		return
	}

	fmt.Printf(yellow.Sprintf("[%s] Worker Node: %s removed with success\n", time.Now().Format("02-01-2006 15:04:05"), node.GetName()))
	deleteAgentCRDInstance(node.Name)
}

func waitForAgent(retryInterval, timeout time.Duration) error {
	address := fmt.Sprintf("%s:%s", agentHOST, agentPORT)
	start := time.Now()

	for {
		// Try to establish a TCP connection to the host
		conn, err := net.DialTimeout("tcp", address, retryInterval)
		if err == nil {
			// If the connection is successful, close it and return
			conn.Close()
			return nil
		}

		// Check if the timeout has been exceeded
		if time.Since(start) > timeout {
			return fmt.Errorf("timeout: Agent is not reachable after %v", timeout)
		}

		// Wait for the retry interval before trying again
		time.Sleep(retryInterval)
	}
}

// generateNonce creates a random nonce of specified byte length
func generateNonce(size int) (string, error) {
	nonce := make([]byte, size)

	// Fill the byte slice with random data
	_, err := rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("error generating nonce: %v", err)
	}

	// Return the nonce as a hexadecimal string
	return hex.EncodeToString(nonce), nil
}

// workerRegistration registers the worker node by calling the identification API
func workerRegistration(node *corev1.Node) bool {
	agentIdentifyURL := fmt.Sprintf("http://%s:%s/agent/worker/identify", agentHOST, agentPORT)
	agentChallengeNodeURL := fmt.Sprintf("http://%s:%s/agent/worker/challenge", agentHOST, agentPORT)
	registrarWorkerCreationURL := fmt.Sprintf("http://%s:%s/worker/create", registrarHOST, registrarPORT)

	err := waitForAgent(5*time.Second, 1*time.Minute)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while contacting Agent: %v\n", time.Now().Format("02-01-2006 15:04:05"), err.Error()))
		return false
	}

	// Call Agent to identify worker data
	workerData, err := callAgentIdentify(agentIdentifyURL)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to call Agent API: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	// Decode EK and AIK
	EK, err := decodePublicKeyFromPEM(workerData.EK)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to parse EK from PEM: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	AIK, err := decodePublicKeyFromPEM(workerData.AIK)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to parse AIK from PEM: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	// Calculate AIK digest
	aikDigest, err := calculateAIKDigest(AIK)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to calculate AIK digest: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	// Generate ephemeral key
	ephemeralKey, err := generateEphemeralKey(32)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to generate ephemeral key: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	nonce, err := generateNonce(8)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to generate challenge nonce: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	// Construct worker challenge payload
	challengePayload := fmt.Sprintf("%s::%s::%s", aikDigest, base64.StdEncoding.EncodeToString(ephemeralKey), nonce)

	// Encrypt the WorkerChallengePayload with the EK public key
	encryptedChallenge, err := encryptWithEK(EK, []byte(challengePayload))
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to encrypt challengePayload with EK: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	// Prepare challenge payload for sending
	workerChallenge := WorkerChallenge{
		WorkerChallenge: encryptedChallenge,
	}

	// Send challenge request to the agent
	challengeResponse, err := sendChallengeRequest(agentChallengeNodeURL, workerChallenge)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to send challenge request: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	decodedHMAC, err := base64.StdEncoding.DecodeString(challengeResponse.HMAC)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to decode HMAC: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	// Verify the HMAC response from the agent
	if err := verifyHMAC([]byte(workerData.UUID), ephemeralKey, decodedHMAC); err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to verify HMAC: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	bootAggregate, hashAlg, err := validateWorkerQuote(challengeResponse.WorkerBootQuote, nonce, AIK)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to validate Worker Quote: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	workerWhitelistCheckRequest := WorkerWhitelistCheckRequest{
		OsName:        node.Status.NodeInfo.OSImage,
		BootAggregate: bootAggregate,
		HashAlg:       hashAlg,
	}

	err = verifyBootAggregate(workerWhitelistCheckRequest)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Worker Boot validation failed: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	workerNode := WorkerNode{
		WorkerId: workerData.UUID,
		Name:     node.GetName(),
		AIK:      workerData.AIK,
	}

	// Create a new worker
	createWorkerResponse, err := createWorker(registrarWorkerCreationURL, &workerNode)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to create Worker Node: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	fmt.Printf(green.Sprintf("[%s] Successfully registered Worker Node: %s\n", time.Now().Format("02-01-2006 15:04:05"), createWorkerResponse.WorkerId))
	createAgentCRDInstance(node.Name)
	return true
}

func verifyBootAggregate(checkRequest WorkerWhitelistCheckRequest) error {
	whitelistProviderWorkerValidateURL := fmt.Sprintf("http://%s:%s/whitelist/worker/os/check", whitelistHOST, whitelistPORT)

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(checkRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal Whitelist check request: %v", err)
	}

	// Make the POST request to the agent
	resp, err := http.Post(whitelistProviderWorkerValidateURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send Whitelist check request: %v", err)
	}

	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Whitelists Provider failed to process check request: %s (status: %d)", string(body), resp.StatusCode)
	}

	return nil
}

// Helper function to call the agent identification API
func callAgentIdentify(url string) (*WorkerResponse, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to call agent identification API: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Agent failed to process identification request: %s (status: %d)", string(body), resp.StatusCode)
	}

	var workerResponse WorkerResponse
	if err := json.Unmarshal(body, &workerResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return &workerResponse, nil
}

func verifySignature(rsaPubKey *rsa.PublicKey, message []byte, signature tpmutil.U16Bytes) error {
	hashed := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], signature)
	return err
}

func validateWorkerQuote(quoteJSON, nonce string, AIK *rsa.PublicKey) (string, string, error) {
	// decode nonce from hex
	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil {
		return "", "", fmt.Errorf("Failed to decode ")
	}

	// Parse inputQuote JSON
	var inputQuote InputQuote
	err = json.Unmarshal([]byte(quoteJSON), &inputQuote)
	if err != nil {
		return "", "", fmt.Errorf("Failed to unmarshal Quote: %v", err)
	}

	// Decode Base64-encoded quote and signature
	quoteBytes, err := base64.StdEncoding.DecodeString(inputQuote.Quote)
	if err != nil {
		return "", "", fmt.Errorf("Failed to decode Quote: %v", err)
	}

	// Decode Base64-encoded quote and signature
	quoteSig, err := base64.StdEncoding.DecodeString(inputQuote.RawSig)
	if err != nil {
		return "", "", fmt.Errorf("Failed to decode Quote: %v", err)
	}

	sig, err := tpm2legacy.DecodeSignature(bytes.NewBuffer(quoteSig))
	if err != nil {
		return "", "", fmt.Errorf("Failed to decode Quote Signature")
	}

	// Verify the signature
	if verifySignature(AIK, quoteBytes, sig.RSA.Signature) != nil {
		return "", "", fmt.Errorf("Quote Signature verification failed")
	}

	// Decode and check for magic TPMS_GENERATED_VALUE.
	attestationData, err := tpm2legacy.DecodeAttestationData(quoteBytes)
	if err != nil {
		return "", "", fmt.Errorf("Decoding Quote attestation data failed: %v", err)
	}
	if attestationData.Type != tpm2legacy.TagAttestQuote {
		return "", "", fmt.Errorf("Expected quote tag, got: %v", attestationData.Type)
	}
	attestedQuoteInfo := attestationData.AttestedQuoteInfo
	if attestedQuoteInfo == nil {
		return "", "", fmt.Errorf("attestation data does not contain quote info")
	}
	if subtle.ConstantTimeCompare(attestationData.ExtraData, nonceBytes) == 0 {
		return "", "", fmt.Errorf("Quote extraData %v did not match expected extraData %v", attestationData.ExtraData, nonceBytes)
	}

	inputPCRs, err := convertPCRs(inputQuote.PCRs.PCRs)
	if err != nil {
		return "", "", fmt.Errorf("Failed to convert PCRs from received Quote")
	}

	quotePCRs := &pb.PCRs{
		Hash: pb.HashAlgo(inputQuote.PCRs.Hash),
		Pcrs: inputPCRs,
	}

	pcrHashAlgo, err := convertToCryptoHash(quotePCRs.GetHash())
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse hash algorithm: %v", err)
	}

	err = validatePCRDigest(attestedQuoteInfo, quotePCRs, pcrHashAlgo)
	if err != nil {
		return "", "", fmt.Errorf("PCRs digest validation failed: %v", err)
	}

	return hex.EncodeToString(attestedQuoteInfo.PCRDigest), quotePCRs.GetHash().String(), nil
}

func convertToCryptoHash(algo pb.HashAlgo) (crypto.Hash, error) {
	switch algo {
	case 4:
		return crypto.SHA1, nil
	case 11:
		return crypto.SHA256, nil
	case 12:
		return crypto.SHA384, nil
	case 13:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %v", algo)
	}
}

func convertPCRs(input map[string]string) (map[uint32][]byte, error) {
	converted := make(map[uint32][]byte)

	// Iterate over the input map
	for key, value := range input {
		// Convert string key to uint32
		keyUint32, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to convert key '%s' to uint32: %v", key, err)
		}

		// Decode base64-encoded value
		valueBytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 value for key '%s': %v", key, err)
		}

		// Add the converted key-value pair to the new map
		converted[uint32(keyUint32)] = valueBytes
	}

	return converted, nil
}

func validatePCRDigest(quoteInfo *tpm2legacy.QuoteInfo, pcrs *pb.PCRs, hash crypto.Hash) error {
	if !SamePCRSelection(pcrs, quoteInfo.PCRSelection) {
		return fmt.Errorf("given PCRs and Quote do not have the same PCR selection")
	}
	pcrDigest := PCRDigest(pcrs, hash)
	if subtle.ConstantTimeCompare(quoteInfo.PCRDigest, pcrDigest) == 0 {
		return fmt.Errorf("given PCRs digest not matching")
	}
	return nil
}

// PCRDigest computes the digest of the Pcrs. Note that the digest hash
// algorithm may differ from the PCRs' hash (which denotes the PCR bank).
func PCRDigest(p *pb.PCRs, hashAlg crypto.Hash) []byte {
	hash := hashAlg.New()
	for i := uint32(0); i < 24; i++ {
		if pcrValue, exists := p.GetPcrs()[i]; exists {
			hash.Write(pcrValue)
		}
	}
	return hash.Sum(nil)
}

// SamePCRSelection checks if the Pcrs has the same PCRSelection as the
// provided given tpm2.PCRSelection (including the hash algorithm).
func SamePCRSelection(p *pb.PCRs, sel tpm2legacy.PCRSelection) bool {
	if tpm2legacy.Algorithm(p.GetHash()) != sel.Hash {
		return false
	}
	if len(p.GetPcrs()) != len(sel.PCRs) {
		return false
	}
	for _, pcr := range sel.PCRs {
		if _, ok := p.Pcrs[uint32(pcr)]; !ok {
			return false
		}
	}
	return true
}

// Helper function to send the challenge request to the agent
func sendChallengeRequest(url string, challenge WorkerChallenge) (*WorkerChallengeResponse, error) {
	// Marshal the challenge struct into JSON
	jsonData, err := json.Marshal(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal challenge payload: %v", err)
	}

	// Send HTTP POST request
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send challenge request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body) // Read the body
		return nil, fmt.Errorf("unexpected response status: %s, response body: %s", resp.Status, string(bodyBytes))
	}

	// Decode the response JSON into the WorkerChallengeResponse struct
	var challengeResponse WorkerChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challengeResponse); err != nil {
		return nil, fmt.Errorf("failed to decode challenge response: %v", err)
	}

	return &challengeResponse, nil
}

// Create a new worker in the registrar
func createWorker(url string, workerNode *WorkerNode) (*NewWorkerResponse, error) {
	jsonData, err := json.Marshal(workerNode)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal worker data: %v", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create worker: %v", err)
	}
	defer resp.Body.Close()

	// Read response body in case of an unexpected status
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected response status when creating worker: %s. Response body: %s", resp.Status, string(body))
	}
	var workerResponse NewWorkerResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&workerResponse); err != nil {
		return nil, fmt.Errorf("failed to decode created worker response: %v", err)
	}
	return &workerResponse, nil
}

func createAgentCRDInstance(nodeName string) {
	// Get the list of pods running on the specified node and attestation namespace
	pods, err := clientset.CoreV1().Pods(attestationNamespace).List(context.TODO(), v1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error getting pods on node %s: %v\n", time.Now().Format("02-01-2006 15:04:05"), nodeName, err))
		return
	}

	// Prepare podStatus array for the Agent CRD spec
	var podStatus []map[string]interface{}
	for _, pod := range pods.Items {
		podName := pod.Name
		tenantID := getTenantIDFromPodName(podName)

		// Skip pods with name prefixed with "agent-"
		if strings.HasPrefix(podName, "agent-") {
			continue
		}

		// Add each pod status to the array
		podStatus = append(podStatus, map[string]interface{}{
			"podName":   podName,
			"tenantID":  tenantID,
			"status":    "Trusted",
			"reason":    "Pod attestation successful",
			"lastCheck": time.Now().Format(time.RFC3339),
		})
	}

	// Construct the Agent CRD instance
	agent := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "example.com/v1",
			"kind":       "Agent",
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("agent-%s", nodeName),
				"namespace": "kube-system",
			},
			"spec": map[string]interface{}{
				"agentName":   fmt.Sprintf("agent-%s", nodeName),
				"agentStatus": "Ready",
				"nodeStatus":  "Trusted",
				"enabled":     true,
				"podStatus":   podStatus,
			},
		},
	}

	// Define the resource to create
	gvr := schema.GroupVersionResource{
		Group:    "example.com", // Group name defined in your CRD
		Version:  "v1",
		Resource: "agents",
	}

	// Create the Agent CRD instance in the kube-system namespace
	_, err = dynamicClient.Resource(gvr).Namespace("kube-system").Create(context.TODO(), agent, v1.CreateOptions{})
	if err != nil {
		fmt.Printf(yellow.Sprintf("[%s] Error creating Agent CRD instance: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	fmt.Printf(green.Sprintf("[%s] Agent CRD instance created for node %s\n", time.Now().Format("02-01-2006 15:04:05"), nodeName))
}

func deployAgentCRD() {
	yamlContent := `
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: agents.example.com
spec:
  group: example.com
  names:
    kind: Agent
    listKind: AgentList
    plural: agents
    singular: agent
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                agentName:
                  type: string
                nodeStatus:
                  type: string
                podStatus:
                  type: array
                  items:
                    type: object
                    properties:
                      podName:
                        type: string
                      tenantID:
                        type: string
                      status:
                        type: string
                      reason:
                        type: string
                      lastCheck:
                        type: string
                        format: date-time
`

	tempFileName := "/tmp/crd.yaml"
	err := ioutil.WriteFile(tempFileName, []byte(yamlContent), 0644)
	if err != nil {
		fmt.Printf(red.Sprintf("Error writing to file: %v\n", err))
		return
	}
	defer func() {
		err := os.Remove(tempFileName)
		if err != nil && !os.IsNotExist(err) {
			fmt.Printf(red.Sprintf("Error cleaning up temporary file: %v\n", err))
		}
	}()

	cmd := exec.Command("kubectl", "apply", "-f", tempFileName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf(red.Sprintf("Error applying YAML file: %v\n", err))
		fmt.Println(red.Println(string(output)))
		return
	}

	fmt.Printf(green.Sprintf("[%s] CRD 'agents.example.com' created successfully\n", time.Now().Format("02-01-2006 15:04:05")))
}

func deleteAgentCRDInstance(nodeName string) {
	// Construct the name of the Agent CRD based on the node name
	agentCRDName := fmt.Sprintf("agent-%s", nodeName)

	// Define the GroupVersionResource for the Agent CRD
	gvr := schema.GroupVersionResource{
		Group:    "example.com", // Group name defined in your CRD
		Version:  "v1",
		Resource: "agents", // Plural form of the CRD resource name
	}

	// Delete the Agent CRD instance in the "kube-system" namespace
	err := dynamicClient.Resource(gvr).Namespace("kube-system").Delete(context.TODO(), agentCRDName, v1.DeleteOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error deleting Agent CRD instance: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	fmt.Printf(yellow.Sprintf("[%s] Agent CRD instance deleted: %s\n", time.Now().Format("02-01-2006 15:04:05"), agentCRDName))
}
func getTenantIDFromPodName(podName string) string {

	parts := strings.Split(podName, "-tenant-")

	// The tenantID is the last part of the split array
	tenantID := parts[len(parts)-1]
	return tenantID
}

// Main function
func main() {
	initializeColors()
	loadEnvironmentVariables()
	configureKubernetesClient()

	deployAgentCRD()
	watchNodes()
}
