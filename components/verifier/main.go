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
	"fmt"
	"github.com/fatih/color"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"io"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type AttestationRequest struct {
	Nonce     string `json:"nonce"`
	PodName   string `json:"podName"`
	PodUID    string `json:"podUID"`
	TenantId  string `json:"tenantId"`
	Signature string `json:"signature,omitempty"`
}

type RegistrarResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
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

type IMAPodEntry struct {
	FilePath string `json:"filePath"`
	FileHash string `json:"fileHash"`
}

type PodWhitelistCheckRequest struct {
	PodImageName string        `json:"podImageName"`
	PodFiles     []IMAPodEntry `json:"podFiles"`
	HashAlg      string        `json:"hashAlg"` // Include the hash algorithm in the request
}

// Color variables for output
var (
	red                  *color.Color
	green                *color.Color
	yellow               *color.Color
	blue                 *color.Color
	clientset            *kubernetes.Clientset
	dynamicClient        dynamic.Interface
	registrarHOST        string
	registrarPORT        string
	agentPORT            string
	attestationNamespace string
	whitelistHOST        string
	whitelistPORT        string
)

// TEST PURPOSE
var attestationSecret = []byte("this_is_a_32_byte_long_secret_k")
var verifierKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuoi/38EDObItiLd1Q8CyXsPaHjOreYqVJYEO4NfCZR2H01LX
rdj/LcpyrB1rKBc4UWI8lroSdhjMJxC62372WvDk9cD5k+iyPwdM+EggpiRfEmHW
F3zob8junyWHW6JInf0+AGhbKgBfMXo9PvAnr5CVeqp2BrstdZtrWVRuQAKip9c7
hl+mHODkE5yb0InHyRe5WWr5P7wtXtAPM6SO8dVk/QWXdsB9rsb+Ejy4LHSIUpHU
OZO8LvGD1rVLO82H4EUXKBFeiOEJjly4HOkvmFe/c/Cma1pM+702X6ULf0/BIMJk
WzD3INdLtk8FE8rIxrrMSnDtmWw9BgGdsDgkpQIDAQABAoIBAAU0UIopI/JlpsCU
QcjQpQlg1IKYNXYQKEYiGiyqyGky0DnUq2DV15TK+7USow08zJz0rTUVXvN9kKCc
ZmI+Yhg6dWDn7+6xBNweU4bv2D1acW6dXTBNk1yfEg1Nqj+jwPvrd2Hih3yeAwnp
27CYWbsbwRfpjp50dXm9Cts0sFjHzdjPlxd28v6jWKjRMoyZuvVis7rE9Zp6y8Yl
MCcHmCAJN/KdfMYHIHbNsjo8hmif//eQCUk4im8dP+5l3Mje4RbYZqSJ0GzhAkgE
+vvQiSlNBObqDJ6pWE/x77VpWY0zf78IqBf8qEXX2LfHKychFmjeBWFZF5eUPGzb
ST3lT3cCgYEA3ohK3BNDz5xFIg/rCPbKisGKB0Ll+bZZ/Wi6AWQltJ7HaG5AXtLV
kIrFs1xFYEFTchuHLgZvfUMqhz/9PEHJRlsMxyXmZAwmzsmr2cQ6J9zmoWWc8sbx
9i54Iab/veFT5UbS71+G9XNZxmkH60tYcpeqrtAZ/0Rj8ndvREUFY88CgYEA1pZ9
5VtxLUsmCqeFI/6Zbbw1RB4flQBDI//AeAtQNZb6qwcdOvLBNLF1SDM8WIcJw1Kx
NPgnTeFAS4f6L37J8wQQ+QDp83W8hGhAKeh3c48sxC6I+BNL/duV6Z7yT7XHFYdq
bxUuELpskk4QTFpwTRb94TlPls4Fa6e+OiwMaUsCgYEAsJLw44Od0QSsjoSW+Lvq
pwM/JNfeZ7Bb44nP3f67NICwtZqWFSeyMkkK6nES03fCYM6bCtgsavZ6rmsF42RH
8z2X/AWEtGo3+OlpJRhhFPRhRDu+t51IrRDeXcWHNAGxckIqaaohCm4HFDqPABL/
EZ5q3t9dYYHA1MoUTdV+m10CgYBfg77n/yrCQWfeaDBgFCxQ5uxCtLHUDbjU5jrS
dB6wq9JJnDILkhAjlzWf/IZI1VqoIT+VVzuPc8q9k/nteB8F13KCk0CPSIGv4gNl
Y/7/ZeREMn5vBY/WoA37Xe93QW8rCwp6BVBqy8AV4z9n7P19otVAkdT2SB+rio+m
rwKbPwKBgEtGHcXZQbo6rmlJo7rToicPMzlQkxHiJA/VogXfEhxLioj12hk7i6jQ
rvFXR5gyK4gO/QkPQuk3vON5l+JLNb1atPnUSPm4jSubHnVLcoKRb8KhrHQLflIQ
QjuOz08OOiJlQjBjWTMHUXfccFV3Bu6BOsFAr44Cspwd3bD3QUV6
-----END RSA PRIVATE KEY-----`

// watchAttestationRequestCRDChanges starts watching for changes to the AttestationRequest CRD
// and processes added, modified, and deleted events.
func watchAttestationRequestCRDChanges(stopCh chan os.Signal) {
	crdGVR := schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "attestationrequests",
	}

	// Start the watch on the AttestationRequest CRD.
	watcher, err := dynamicClient.Resource(crdGVR).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("Error watching Attestation Request CRD: %v\n", err))
		return
	}
	defer watcher.Stop()

	for {
		select {
		case event := <-watcher.ResultChan():
			if event.Type == "" {
				continue
			}
			processAttestationRequestCRDEvent(event)
		case <-stopCh:
			fmt.Println(green.Sprintf("Stopping Attestation Request CRD watcher..."))
			return
		}
	}
}

// processAttestationRequestCRDEvent handles different types of CRD events (Added, Modified, Deleted).
func processAttestationRequestCRDEvent(event watch.Event) {
	switch event.Type {
	case watch.Added:
		fmt.Printf(green.Sprintf("[%s] Attestation Request CRD Added:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatCRD(event.Object)))
		podAttestation(event.Object)
		deleteAttestationRequestCRDInstance(event.Object)

	case watch.Modified:
		fmt.Printf(yellow.Sprintf("[%s] Attestation Request CRD Modified:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatCRD(event.Object)))

	case watch.Deleted:
		fmt.Printf(yellow.Sprintf("[%s] Attestation Request CRD Deleted:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatCRD(event.Object)))

	default:
		fmt.Printf(red.Sprintf("[%s] Unknown event type: %v\n", time.Now().Format("02-01-2006 15:04:05"), event.Type))
	}
}

// initializeColors sets up color variables for console output.
func initializeColors() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
}

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	agentPORT = getEnv("AGENT_PORT", "30000")
	registrarHOST = getEnv("REGISTRAR_HOST", "localhost")
	registrarPORT = getEnv("REGISTRAR_PORT", "8080")
	attestationNamespace = getEnv("ATTESTATION_NAMESPACE", "default")
	whitelistHOST = getEnv("WHITELIST_HOST", "localhost")
	whitelistPORT = getEnv("WHITELIST_PORT", "9090")
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

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() chan os.Signal {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	return stopCh
}

func deleteAttestationRequestCRDInstance(crdObj interface{}) {
	// Assert that crdObj is of type *unstructured.Unstructured
	unstructuredObj, ok := crdObj.(*unstructured.Unstructured)
	if !ok {
		fmt.Printf(red.Sprintf("[%s] Failed to cast the CRD object to *unstructured.Unstructured\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	// Define the GroupVersionResource (GVR) for your CRD
	gvr := schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "attestationrequests", // plural name of the CRD
	}

	// Extract the namespace and name of the CRD from the unstructuredObj
	namespace := unstructuredObj.GetNamespace()
	resourceName := unstructuredObj.GetName()

	// Delete the AttestationRequest CR in the given namespace
	err := dynamicClient.Resource(gvr).Namespace(namespace).Delete(context.TODO(), resourceName, metav1.DeleteOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to delete AttestationRequest: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	fmt.Printf(yellow.Sprintf("[%s] AttestationRequest: %s in namespace: %s deleted successfully\n", time.Now().Format("02-01-2006 15:04:05"), resourceName, namespace))
	return
}

// GenerateNonce creates a random nonce of specified byte length
func GenerateNonce(size int) (string, error) {
	nonce := make([]byte, size)

	// Fill the byte slice with random data
	_, err := rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("error generating nonce: %v", err)
	}

	// Return the nonce as a hexadecimal string
	return hex.EncodeToString(nonce), nil
}

// Utility function: Sign a message using the provided private key
func signMessage(privateKeyPEM string, message []byte) (string, error) {
	// Decode the PEM-encoded private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse the private key from the PEM block
	rsaPrivKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse PKCS1 private key: %v", err)
	}

	// Hash the message using SHA256
	hashed := sha256.Sum256(message)

	// Sign the hashed message using the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Encode the signature in Base64 and return it
	return base64.StdEncoding.EncodeToString(signature), nil
}

func extractNodeName(agentName string) (string, error) {
	// Define the prefix that precedes the nodeName
	prefix := "agent-"

	// Check if the agentName starts with the prefix
	if len(agentName) > len(prefix) && agentName[:len(prefix)] == prefix {
		// Extract the nodeName by removing the prefix
		nodeName := agentName[len(prefix):]
		return nodeName, nil
	}

	// Return an error if the agentName does not start with the expected prefix
	return "", fmt.Errorf("invalid agentName format: %s", agentName)
}

func podAttestation(obj interface{}) {
	spec := formatCRD(obj)

	podName, exists := spec["podName"].(string)
	if !exists {
		fmt.Println(red.Println("[%s] Error: Missing 'podName' field in Attestation Request CRD"))
		return
	}

	podUID, exists := spec["podUID"].(string)
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'podUID' field in Attestation Request CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	tenantId, exists := spec["tenantID"].(string)
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'tenantID' field in Attestation Request CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	agentName, exists := spec["agentName"].(string)
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'agentName' field in Attestation Request CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	agentIP, exists := spec["agentIP"].(string)
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'agentIP' field in Attestation Request CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	hmacValue, exists := spec["hmac"].(string)
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'hmac' field in Attestation Request CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	decodedHMAC, err := base64.StdEncoding.DecodeString(hmacValue)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to decode HMAC: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	integrityMessage := fmt.Sprintf("%s::%s::%s::%s::%s", podName, podUID, tenantId, agentName, agentIP)
	err = verifyHMAC([]byte(integrityMessage), attestationSecret, decodedHMAC)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while computing HMAC, Attestation Request for pod: %s is invalid\n", time.Now().Format("02-01-2006 15:04:05"), podName))
		return
	}

	nonce, err := GenerateNonce(16)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while generating nonce\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	attestationRequest := AttestationRequest{
		Nonce:    nonce,
		PodName:  podName,
		PodUID:   podUID,
		TenantId: tenantId,
	}

	attestationRequestJSON, err := json.Marshal(attestationRequest)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error serializing Attestation Request\n", time.Now().Format("02-01-2006 15:04:05")))
	}

	attestationRequestSignature, err := signMessage(verifierKey, attestationRequestJSON)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error signing Attestation Request\n", time.Now().Format("02-01-2006 15:04:05")))
	}

	attestationRequest.Signature = attestationRequestSignature

	attestationResponse, err := sendAttestationRequestToAgent(agentIP, agentPORT, attestationRequest)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while sending Attestation Request to Agent: %s for pod: %s: %s\n", time.Now().Format("02-01-2006 15:04:05"), agentName, podName, err.Error()))
		return
	}

	workerName, err := extractNodeName(agentName)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error verifying Attestation Evidence: invalid Worker name\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	evidenceJSON, err := json.Marshal(attestationResponse.Evidence)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error serializing Evidence\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	// process Evidence
	_, err = verifyWorkerSignature(workerName, string(evidenceJSON), attestationResponse.Signature)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Evidence Signature Verification failed: %s\n", time.Now().Format("02-01-2006 15:04:05"), err.Error()))
		return
	}

	PCRDigest, hashAlg, err := validateWorkerQuote(workerName, attestationResponse.Evidence.WorkerQuote, nonce)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to validate Worker Quote: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	IMAPodEntries, err := IMAAnalysis(attestationResponse.Evidence.WorkerIMA, PCRDigest, podUID)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to validate IMA measurement log: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	podImageName, err := getPodImageNameByUID(podUID)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to get image of Pod: %s: %v\n", time.Now().Format("02-01-2006 15:04:05"), podName, err))
		return
	}

	podCheckRequest := PodWhitelistCheckRequest{
		PodImageName: podImageName,
		PodFiles:     IMAPodEntries,
		HashAlg:      hashAlg,
	}

	err = verifyPodFilesIntegrity(podCheckRequest)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to verify integrity of files executed by Pod: %s: %v\n", time.Now().Format("02-01-2006 15:04:05"), podName, err))
		return
	}

	fmt.Printf(green.Sprintf("[%s] Attestation of Pod: %s succeeded\n", time.Now().Format("02-01-2006 15:04:05"), podName))
	return
}

// getPodImageByUID retrieves the image of a pod given its UID
func getPodImageNameByUID(podUID string) (string, error) {
	// List all pods in the cluster (you may want to filter by namespace in production)
	pods, err := clientset.CoreV1().Pods(attestationNamespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to list pods: %v", err)
	}

	// Iterate over the pods to find the one with the matching UID
	for _, pod := range pods.Items {
		if string(pod.UID) == podUID {
			// If pod found, return the image of the first container (or modify to fit your need)
			if len(pod.Spec.Containers) > 0 {
				return pod.Spec.Containers[0].Image, nil
			}
			return "", fmt.Errorf("no containers found in pod with UID %s", podUID)
		}
	}
	// If no pod is found with the given UID
	return "", fmt.Errorf("no pod found with UID %s", podUID)
}

// extractSHADigest extracts the actual hex digest from a string with the format "sha<algo>:<hex_digest>"
func extractSHADigest(input string) (string, error) {
	// Define a regular expression to match the prefix "sha<number>:"
	re := regexp.MustCompile(`^sha[0-9]+:`)

	if re.MatchString(input) {
		// Remove the matching prefix and return the remaining part (hex digest)
		return re.ReplaceAllString(input, ""), nil
	}
	return "", fmt.Errorf("input does not have a valid sha<algo>: prefix")
}

// IMAAnalysis checks the integrity of the IMA measurement log against the received Quote and returns the entries related to the pod being attested for statical analysis of executed software
func IMAAnalysis(IMAMeasurementLog, PCRDigest, podUID string) ([]IMAPodEntry, error) {
	// Step 1: Decode the base64-encoded IMA log
	decodedLog, err := base64.StdEncoding.DecodeString(IMAMeasurementLog)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IMA measurement log: %v", err)
	}

	// Step 2: Convert the decoded log to a string and split it into lines
	logLines := strings.Split(string(decodedLog), "\n")

	var IMAPodEntries []IMAPodEntry

	// Step 3: Initialize the hash computation
	hash := sha256.New()
	initialHash := [32]byte{} // Initial zero hash
	hash.Write(initialHash[:])

	// Step 4: Iterate through each line and extract the second element
	for _, IMALine := range logLines {
		// Split the line by whitespace
		IMAFields := strings.Fields(IMALine)
		if len(IMAFields) < 7 {
			return nil, fmt.Errorf("IMA measurement log integrity check failed: found entry not compliant with template")
		}

		// Decode the template hash field (second element)
		templateHashField, err := hex.DecodeString(IMAFields[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode a template hash field from IMA measurement log: %v", err)
		}

		// Extract the cgroup path (fifth element)
		cgroupPathField := IMAFields[4]

		// Check if the cgroup path contains the podUID
		if checkPodUIDMatch(cgroupPathField, podUID) {
			// Extract the file hash and file path (sixth and seventh elements)
			fileHash, err := extractSHADigest(IMAFields[5])
			if err != nil {
				return nil, fmt.Errorf("failed to decode file hash field: %v", err)
			}
			filePath := IMAFields[6]
			IMAPodEntries = append(IMAPodEntries, IMAPodEntry{
				FilePath: filePath,
				FileHash: fileHash,
			})
		}

		// Concatenate previous hash and the new element
		previousHash := hash.Sum(nil)
		dataToHash := append(previousHash, templateHashField...)

		// Compute the new hash
		hash.Reset() // Reset the hash to start fresh
		hash.Write(dataToHash)
	}

	// Get the final computed hash
	cumulativeHashIMA := hash.Sum(nil)

	// Convert the final hash to a hex string for comparison
	cumulativeHashIMAHex := hex.EncodeToString(cumulativeHashIMA)

	// Compare the computed hash with the provided PCRDigest
	// TODO delete node from cluster?
	if cumulativeHashIMAHex != PCRDigest {
		return nil, fmt.Errorf("IMA measurement log integrity check failed: computed hash does not match PCRDigest")
	}

	// Return the collected IMA pod entries
	return IMAPodEntries, nil
}

func checkPodUIDMatch(path, podUID string) bool {
	// Regex pattern for matching a UUID inside a string (case-insensitive)
	regexPattern := fmt.Sprintf(`\/pod%s\/`, regexp.QuoteMeta(podUID))

	// Compile the regex
	r, err := regexp.Compile(regexPattern)
	if err != nil {
		fmt.Printf(red.Sprintf("Invalid Pod UID regex pattern: %v\n", err))
		return false
	}
	// Check if the path contains the UUID
	return r.MatchString(path)
}

// Verify the provided signature by contacting Registrar API
func verifyWorkerSignature(workerName, message, signature string) (bool, error) {
	registrarURL := fmt.Sprintf("http://%s:%s/worker/verify", registrarHOST, registrarPORT)
	payload := map[string]string{
		"name":      workerName,
		"message":   message,
		"signature": signature,
	}

	// Marshal payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Make POST request to the Registrar API
	resp, err := http.Post(registrarURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the response status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("failed to verify signature: %s (status: %d)", string(body), resp.StatusCode)
	}

	// Parse the response into the RegistrarResponse struct
	var registrarResp RegistrarResponse
	if err := json.Unmarshal(body, &registrarResp); err != nil {
		return false, fmt.Errorf("failed to parse response: %v", err)
	}

	// Verify if the status and message indicate success
	return registrarResp.Status == "success" && registrarResp.Message == "Signature verification successful", nil
}

func validateWorkerQuote(workerName, quoteJSON, nonce string) (string, string, error) {
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
	quoteSignatureIsValid, err := verifyWorkerSignature(workerName, string(quoteBytes), base64.StdEncoding.EncodeToString(sig.RSA.Signature))
	if !quoteSignatureIsValid {
		return "", "", fmt.Errorf("Quote Signature verification failed: %v", err)
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

	PCRHashAlgo, err := convertToCryptoHash(quotePCRs.GetHash())
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse hash algorithm: %v", err)
	}

	err = validatePCRDigest(attestedQuoteInfo, quotePCRs, PCRHashAlgo)
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

func verifyPodFilesIntegrity(checkRequest PodWhitelistCheckRequest) error {
	whitelistProviderWorkerValidateURL := fmt.Sprintf("http://%s:%s/whitelist/pod/check", whitelistHOST, whitelistPORT)

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

func sendAttestationRequestToAgent(agentIP, agentPort string, attestationRequest AttestationRequest) (AttestationResponse, error) {
	// contact the target Agent to request attestation evidence
	agentRequestAttestationURL := fmt.Sprintf("http://%s:%s/agent/pod/attest", agentIP, agentPort)

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(attestationRequest)
	if err != nil {
		return AttestationResponse{}, fmt.Errorf("failed to marshal attestation request: %v", err)
	}

	// Make the POST request to the agent
	resp, err := http.Post(agentRequestAttestationURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return AttestationResponse{}, fmt.Errorf("failed to send attestation request: %v", err)
	}

	defer resp.Body.Close()

	if resp.Body == nil {
		return AttestationResponse{}, fmt.Errorf("response body is empty")
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return AttestationResponse{}, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return AttestationResponse{}, fmt.Errorf("Agent failed to process attestation request: %s (status: %d)", string(body), resp.StatusCode)
	}

	var agentResponse struct {
		AttestationResponse AttestationResponse `json:"attestationResponse"`
		Message             string              `json:"message"`
		Status              string              `json:"status"`
	}

	// Parse the response body into the AttestationResponse struct
	err = json.Unmarshal(body, &agentResponse)
	if err != nil {
		return AttestationResponse{}, fmt.Errorf("failed to unmarshal attestation response: %v", err)
	}

	// Return the parsed attestation response
	return agentResponse.AttestationResponse, nil
}

// Helper function to verify HMAC
func verifyHMAC(message, key, providedHMAC []byte) error {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	expectedHMAC := h.Sum(nil)

	if !hmac.Equal(expectedHMAC, providedHMAC) {
		return fmt.Errorf("HMAC verification failed")
	}
	return nil
}

func formatCRD(obj interface{}) map[string]interface{} {
	agentCRD, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		fmt.Println(red.Println("Error: Missing 'spec' field in Agent CRD"))
		return nil
	}

	spec, specExists := agentCRD["spec"].(map[string]interface{})
	if !specExists {
		fmt.Println(red.Println("Error: Missing 'spec' field in Agent CRD"))
		return nil
	}
	return spec
}

func deployAttestationRequestCRD() {
	yamlContent := `
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: attestationrequests.example.com  
spec:
  group: example.com
  names:
    kind: AttestationRequest
    listKind: AttestationRequestList
    plural: attestationrequests   
    singular: attestationrequest  
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
                podName:
                  type: string
                podUID:
                  type: string
                tenantID:
                  type: string
                agentName:
                  type: string
                agentIP:
                  type: string
                issued:
                  type: string
                  format: date-time
                hmac:
                  type: string
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

	fmt.Printf(green.Sprintf("[%s] CRD 'attestationRequest.example.com' created successfully\n", time.Now().Format("02-01-2006 15:04:05")))
}

func main() {
	initializeColors()
	loadEnvironmentVariables()
	configureKubernetesClient()

	stopCh := setupSignalHandler()
	deployAttestationRequestCRD()

	watchAttestationRequestCRDChanges(stopCh)

	fmt.Printf(green.Sprintf("Watching Attestation Request CRD changes...\n\n"))
	<-stopCh
}
