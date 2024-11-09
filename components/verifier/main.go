package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/fatih/color"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"io"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1clientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
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
	"log"
	"net/http"
	"os"
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

type IMAEntry struct {
	FilePath string `json:"filePath"`
	FileHash string `json:"fileHash"`
}

type PodWhitelistCheckRequest struct {
	PodImageName   string     `json:"podImageName"`
	PodImageDigest string     `json:"podImageDigest"`
	PodFiles       []IMAEntry `json:"podFiles"`
	HashAlg        string     `json:"hashAlg"` // Include the hash algorithm in the request
}

type ContainerRuntimeCheckRequest struct {
	ContainerRuntimeName         string     `json:"containerRuntimeName"`
	ContainerRuntimeDependencies []IMAEntry `json:"containerRuntimeDependencies"`
	HashAlg                      string     `json:"hashAlg"` // Include the hash algorithm in the request
}

type AttestationResult struct {
	Agent      string
	Target     string
	TargetType string
	Result     string
	Reason     string
}

const COLON_BYTE = byte(58) // ASCII code for ":"
const NULL_BYTE = byte(0)
const containerRuntimeDependencies = "/usr/bin/containerd:/usr/bin/containerd:/usr/lib/systemd/systemd:swapper/0"
const containerRuntimeName = "/usr/bin/containerd-shim-runc-v2"

// Color variables for output
var (
	red                          *color.Color
	green                        *color.Color
	yellow                       *color.Color
	blue                         *color.Color
	clientset                    *kubernetes.Clientset
	dynamicClient                dynamic.Interface
	apiExtensionsClient          *apiextensionsv1clientset.Clientset
	registrarHOST                string
	registrarPORT                string
	attestationNamespaces        string
	attestationEnabledNamespaces []string
	whitelistHOST                string
	whitelistPORT                string
	attestationSecret            []byte
	verifierPrivateKey           string
)

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
		attestationResult, failReason := podAttestation(event.Object)
		if attestationResult != nil {
			updateAgentCRDWithAttestationResult(attestationResult)
		}
		if attestationResult == nil && failReason != nil {
			fmt.Printf(yellow.Sprintf("[%s] Error while processing Attestation request: discarded due to error: %v\n", time.Now().Format("02-01-2006 15:04:05"), failReason))
		}
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
	registrarHOST = getEnv("REGISTRAR_HOST", "localhost")
	registrarPORT = getEnv("REGISTRAR_PORT", "8080")
	attestationNamespaces = getEnv("ATTESTATION_NAMESPACES", "[\"default\"]")
	whitelistHOST = getEnv("WHITELIST_HOST", "localhost")
	whitelistPORT = getEnv("WHITELIST_PORT", "9090")
	verifierPrivateKey = getEnv("VERIFIER_PRIVATE_KEY", "")
	attestationSecret = []byte(getEnv("ATTESTATION_SECRET", ""))
	// setting namespaces allowed for attestation: only pods deployed within them can be attested
	err := json.Unmarshal([]byte(attestationNamespaces), &attestationEnabledNamespaces)
	if err != nil {
		log.Fatalf("Failed to parse 'ATTESTATION_NAMESPACES' content: %v", err)
	}
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		if key == "ATTESTATION_NAMESPACES" {
			fmt.Printf(yellow.Sprintf("[%s] '%s' environment variable missing: setting default value: ['default']\n", time.Now().Format("02-01-2006 15:04:05"), key))
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
	apiExtensionsClient, err = apiextensionsv1clientset.NewForConfig(config)
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

	resourceName := unstructuredObj.GetName()

	// Delete the AttestationRequest CR in the given namespace
	err := dynamicClient.Resource(gvr).Namespace("attestation-system").Delete(context.TODO(), resourceName, metav1.DeleteOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to delete AttestationRequest: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	fmt.Printf(yellow.Sprintf("[%s] AttestationRequest: %s deleted successfully\n", time.Now().Format("02-01-2006 15:04:05"), resourceName))
	return
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

// getNodePort returns the NodePort for a given service in a namespace
func getAgentPort(agentName string) (string, error) {
	agentServiceName := fmt.Sprintf("%s-service", agentName)

	// Get the Service from the given namespace
	service, err := clientset.CoreV1().Services("attestation-system").Get(context.TODO(), agentServiceName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get service: %v", err)
	}

	// Iterate through the service ports to find a NodePort
	for _, port := range service.Spec.Ports {
		if port.NodePort != 0 {
			return fmt.Sprintf("%d", port.NodePort), nil
		}
	}

	return "", fmt.Errorf("no NodePort found for service %s", agentServiceName)
}

func podAttestation(obj interface{}) (*AttestationResult, error) {
	spec := formatCRD(obj)

	podName, exists := spec["podName"].(string)
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'podName' field in Attestation Request CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Missing 'podName' field in Attestation Request CRD")
	}

	podUID, exists := spec["podUID"].(string)
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'podUID' field in Attestation Request CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("podUID 'podName' field in Attestation Request CRD")
	}

	tenantId, exists := spec["tenantID"].(string)
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'tenantID' field in Attestation Request CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Missing 'tenantID' field in Attestation Request CRD")
	}

	agentName, exists := spec["agentName"].(string)
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'agentName' field in Attestation Request CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Missing 'agentName' field in Attestation Request CRD")
	}

	agentIP, exists := spec["agentIP"].(string)
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'agentIP' field in Attestation Request CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Missing 'agentIP' field in Attestation Request CRD")
	}

	hmacValue, exists := spec["hmac"].(string)
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'hmac' field in Attestation Request CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Missing 'hmac' field in Attestation Request CRD")
	}

	decodedHMAC, err := base64.StdEncoding.DecodeString(hmacValue)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to decode HMAC: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return nil, fmt.Errorf("failed to decode HMAC: %v", err)
	}

	integrityMessage := fmt.Sprintf("%s::%s::%s::%s::%s", podName, podUID, tenantId, agentName, agentIP)
	err = verifyHMAC([]byte(integrityMessage), attestationSecret, decodedHMAC)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while computing HMAC, Attestation Request for pod: %s is invalid\n", time.Now().Format("02-01-2006 15:04:05"), podName))
		return nil, fmt.Errorf("Invalid Attestation request: %v", err)
	}

	nonce, err := generateNonce(16)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while generating nonce\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Failed to generate nonce to be sent to the Agent")
	}

	attestationRequest := AttestationRequest{
		Nonce:    nonce,
		PodName:  podName,
		PodUID:   podUID,
		TenantId: tenantId,
	}

	attestationRequestJSON, err := json.Marshal(attestationRequest)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while serializing Attestation Request\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Error while serializing Attestation Request")
	}

	attestationRequestSignature, err := signMessage(verifierPrivateKey, attestationRequestJSON)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error signing Attestation Request\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Error while signing Attestation Request")
	}

	attestationRequest.Signature = attestationRequestSignature

	agentPort, err := getAgentPort(agentName)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while sending Attestation Request to Agent: %s for pod: %s: %s\n", time.Now().Format("02-01-2006 15:04:05"), agentName, podName, err.Error()))
		return nil, fmt.Errorf("Error while sending Attestation Request to Agent: service port not found")
	}

	attestationResponse, err := sendAttestationRequestToAgent(agentIP, agentPort, attestationRequest)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while sending Attestation Request to Agent: %s for pod: %s: %s\n", time.Now().Format("02-01-2006 15:04:05"), agentName, podName, err.Error()))
		return nil, fmt.Errorf("Error while sending Attestation Request to Agent")

	}

	workerName, err := extractNodeName(agentName)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while verifying Attestation Evidence: invalid Worker name\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Error while verifying Attestation Evidence: invalid Worker name")
	}

	evidenceDigest, err := computeEvidenceDigest(attestationResponse.Evidence)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error computing Evidence digest\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Error computing Evidence digest")
	}

	// process Evidence
	_, err = verifyWorkerSignature(workerName, evidenceDigest, attestationResponse.Signature)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Evidence Signature Verification failed: %s\n", time.Now().Format("02-01-2006 15:04:05"), err.Error()))
		return &AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     "UNTRUSTED",
			Reason:     "Evidence Signature verification failed",
		}, fmt.Errorf("Evidence Signature verification failed")
	}

	PCR10Digest, hashAlg, err := validateWorkerQuote(workerName, attestationResponse.Evidence.WorkerQuote, nonce)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to validate Worker Quote: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return &AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     "UNTRUSTED",
			Reason:     "Error while validating Worker Quote",
		}, fmt.Errorf("Error while validating Worker Quote")
	}

	IMAPodEntries, IMAContainerRuntimeEntries, err := IMAVerification(attestationResponse.Evidence.WorkerIMA, PCR10Digest, podUID)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to validate IMA measurement log: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return &AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     "UNTRUSTED",
			Reason:     "Failed to validate IMA Measurement log",
		}, fmt.Errorf("Failed to validate IMA Measurement log")
	}

	podImageName, podImageDigest, err := getPodImageDataByUID(podUID)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to get image name and digest of Pod: %s: %v\n", time.Now().Format("02-01-2006 15:04:05"), podName, err))
		return &AttestationResult{
			Agent:      agentName,
			Target:     podName,
			TargetType: "Pod",
			Result:     "UNTRUSTED",
			Reason:     "Failed to get image name and digest of attested Pod",
		}, fmt.Errorf("Failed to get image name of attested Pod")
	}

	podCheckRequest := PodWhitelistCheckRequest{
		PodImageName:   podImageName,
		PodImageDigest: podImageDigest,
		PodFiles:       IMAPodEntries,
		HashAlg:        hashAlg,
	}

	containerRuntimeCheckRequest := ContainerRuntimeCheckRequest{
		ContainerRuntimeName:         containerRuntimeName,
		ContainerRuntimeDependencies: IMAContainerRuntimeEntries,
		HashAlg:                      hashAlg,
	}

	err = verifyContainerRuntimeIntegrity(containerRuntimeCheckRequest)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to verify integrity of Container Runtime: %s: %v\n", time.Now().Format("02-01-2006 15:04:05"), containerRuntimeCheckRequest.ContainerRuntimeName, err))
		return &AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     "UNTRUSTED",
			Reason:     "Failed to verify integrity of Container Runtime",
		}, fmt.Errorf("Failed to verify integrity of Container Runtime")
	}

	err = verifyPodFilesIntegrity(podCheckRequest)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to verify integrity of files executed by Pod: %s: %v\n", time.Now().Format("02-01-2006 15:04:05"), podName, err))
		return &AttestationResult{
			Agent:      agentName,
			Target:     podName,
			TargetType: "Pod",
			Result:     "UNTRUSTED",
			Reason:     "Failed to verify integrity of files executed by attested Pod",
		}, fmt.Errorf("Failed to verify integrity of files executed by Pod")
	}

	fmt.Printf(green.Sprintf("[%s] Attestation of Pod: %s succeeded\n", time.Now().Format("02-01-2006 15:04:05"), podName))
	return &AttestationResult{
		Agent:      agentName,
		Target:     podName,
		TargetType: "Pod",
		Result:     "TRUSTED",
		Reason:     "Attestation ended with success",
	}, nil
}

func verifyContainerRuntimeIntegrity(checkRequest ContainerRuntimeCheckRequest) error {
	whitelistProviderWorkerValidateURL := fmt.Sprintf("http://%s:%s/whitelist/container/runtime/check", whitelistHOST, whitelistPORT)

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(checkRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal Whitelist check request: %v", err)
	}

	log.Printf(string(jsonPayload))

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

// getPodImageDataByUID retrieves the image and its digest of a pod given its UID
func getPodImageDataByUID(podUID string) (string, string, error) {
	// List all pods in the cluster (you may want to filter by namespace in production)
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return "", "", fmt.Errorf("failed to list pods: %v", err)
	}

	// Iterate over the pods to find the one with the matching UID
	for _, pod := range pods.Items {
		if string(pod.UID) == podUID {
			// If pod found, return the image and its digest (if available)
			if len(pod.Spec.Containers) > 0 {
				imageName := pod.Spec.Containers[0].Image
				imageDigest := ""
				// Check if image digest is available
				for _, status := range pod.Status.ContainerStatuses {
					if status.Name == pod.Spec.Containers[0].Name && status.ImageID != "" {
						imageDigest = status.ImageID
						return imageName, imageDigest, nil
					}
				}
				return "", "", fmt.Errorf("no image digest found in pod with UID %s", podUID)
			}
			return "", "", fmt.Errorf("no containers found in pod with UID %s", podUID)
		}
	}
	// If no pod is found with the given UID
	return "", "", fmt.Errorf("no pod found with UID %s", podUID)
}

// extractSHADigest extracts the algorithm (e.g., "sha256") and the actual hex digest from a string with the format "sha<algo>:<hex_digest>"
func extractSHADigest(input string) (string, string, error) {
	// Define a regular expression to match the prefix "sha<number>:" followed by the hex digest
	re := regexp.MustCompile(`^sha[0-9]+:`)

	// Check if the input matches the expected format
	if matches := re.FindStringSubmatch(input); matches != nil {
		fileHashElements := strings.Split(input, ":")

		return fileHashElements[0], fileHashElements[1], nil
	}

	return "", "", fmt.Errorf("input does not have a valid sha<algo>:<hex_digest> format")
}

// Helper function to compute the new hash by concatenating previous hash and template hash
func extendIMAEntries(previousHash []byte, templateHash string) ([]byte, error) {
	// Create a new SHA context
	hash := sha256.New()

	// Decode the template hash from hexadecimal
	templateHashBytes, err := hex.DecodeString(templateHash)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode template hash field: %v", err)
	}

	// Concatenate previous hash and the new template hash
	dataToHash := append(previousHash, templateHashBytes...)

	// Compute the new hash
	hash.Write(dataToHash)
	return hash.Sum(nil), nil
}

// IMAVerification checks the integrity of the IMA measurement log against the received Quote and returns the entries related to the pod being attested for statical analysis of executed software and the AttestationResult
func IMAVerification(IMAMeasurementLog, PCR10Digest, podUID string) ([]IMAEntry, []IMAEntry, error) {
	isIMAValid := false

	decodedLog, err := base64.StdEncoding.DecodeString(IMAMeasurementLog)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode IMA measurement log: %v", err)
	}

	logLines := strings.Split(string(decodedLog), "\n")
	if len(logLines) > 0 && logLines[len(logLines)-1] == "" {
		logLines = logLines[:len(logLines)-1] // Remove the last empty line --> each entry adds a \n so last line will add an empty line
	}
	uniquePodEntries := make(map[string]IMAEntry)
	uniqueContainerRuntimeEntries := make(map[string]IMAEntry)

	// initial PCR configuration
	previousHash := make([]byte, 32)

	// Iterate through each line and extract relevant fields
	for idx, IMALine := range logLines {
		// Split the line by whitespace
		IMAFields := strings.Fields(IMALine)
		if len(IMAFields) < 7 {
			return nil, nil, fmt.Errorf("IMA measurement log integrity check failed: entry %d not compliant with template: %s", idx, IMALine)
		}

		templateHashField := IMAFields[1]
		depField := IMAFields[3]
		cgroupPathField := IMAFields[4]
		fileHashField := IMAFields[5]
		filePathField := IMAFields[6]

		hashAlgo, fileHash, err := extractSHADigest(fileHashField)
		if err != nil {
			return nil, nil, fmt.Errorf("IMA measurement log integrity check failed: entry: %d file hash is invalid: %s", idx, IMALine)
		}

		extendValue, err := validateIMAEntry(templateHashField, depField, cgroupPathField, hashAlgo, fileHash, filePathField)
		if err != nil {
			return nil, nil, fmt.Errorf("IMA measurement log integrity check failed: entry: %d is invalid: %s", idx, IMALine)
		}

		// Use the helper function to extend ML cumulative hash with the newly computed template hash
		extendedHash, err := extendIMAEntries(previousHash, extendValue)
		if err != nil {
			return nil, nil, fmt.Errorf("Error computing hash at index %d: %v\n", idx, err)
		}

		// Update the previous hash for the next iteration
		previousHash = extendedHash
		if !isIMAValid && hex.EncodeToString(extendedHash) == PCR10Digest {
			isIMAValid = true
		}

		// check if entry belongs to container or is pure a host measurement, otherwise after having computed the extend hash, go to next entry in IMA ML
		if !strings.Contains(depField, "containerd") {
			continue
		}

		// entry is host container-related not a pod entry
		if filePathField == containerRuntimeName || depField == containerRuntimeDependencies {
			// Create a unique key by combining filePath and fileHash
			entryKey := fmt.Sprintf("%s:%s", filePathField, fileHash)

			// Add the entry to the map if it doesn't exist
			if _, exists := uniqueContainerRuntimeEntries[entryKey]; !exists {
				uniqueContainerRuntimeEntries[entryKey] = IMAEntry{
					FilePath: filePathField,
					FileHash: fileHash,
				}
			}
			continue
		}

		// Check if the cgroup path contains the podUID
		if checkPodUIDMatch(cgroupPathField, podUID) {

			// Create a unique key by combining filePath and fileHash
			entryKey := fmt.Sprintf("%s:%s", filePathField, fileHash)

			// Add the entry to the map if it doesn't exist
			if _, exists := uniquePodEntries[entryKey]; !exists {
				uniquePodEntries[entryKey] = IMAEntry{
					FilePath: filePathField,
					FileHash: fileHash,
				}
			}
		}
	}

	// Convert the final hash to a hex string for comparison
	cumulativeHashIMAHex := hex.EncodeToString(previousHash)
	// Compare the computed hash with the provided PCR10Digest
	if cumulativeHashIMAHex != PCR10Digest {
		return nil, nil, fmt.Errorf("IMA measurement log integrity check failed: computed hash does not match quote value")
	}

	// Convert the unique entries back to a slice
	IMAPodEntries := make([]IMAEntry, 0, len(uniquePodEntries))
	for _, entry := range uniquePodEntries {
		IMAPodEntries = append(IMAPodEntries, entry)
	}

	IMAContainerRuntimeEntries := make([]IMAEntry, 0, len(uniqueContainerRuntimeEntries))
	for _, entry := range uniqueContainerRuntimeEntries {
		IMAContainerRuntimeEntries = append(IMAContainerRuntimeEntries, entry)
	}

	// Return the collected IMA pod entries
	return IMAPodEntries, IMAContainerRuntimeEntries, nil
}

func computeIMAEntryHashes(packedDep, packedCgroup, packedFileHash, packedFilePath []byte) (string, string) {
	packedTemplateEntry := append(packedDep, packedCgroup...)
	packedTemplateEntry = append(packedTemplateEntry, packedFileHash...)
	packedTemplateEntry = append(packedTemplateEntry, packedFilePath...)
	sha1Hash := sha1.Sum(packedTemplateEntry)
	sha256Hash := sha256.Sum256(packedTemplateEntry)

	return hex.EncodeToString(sha1Hash[:]), hex.EncodeToString(sha256Hash[:])
}

// Function to pack IMA hash
func packIMAHash(hashAlg string, fileHash []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Pack total length (algorithm + 2 extra bytes + hash length)
	totalLen := uint32(len(hashAlg) + 2 + len(fileHash))
	if err := binary.Write(buf, binary.LittleEndian, totalLen); err != nil {
		return nil, fmt.Errorf("failed to pack total length: %v", err)
	}

	// Pack algorithm
	if _, err := buf.Write([]byte(hashAlg)); err != nil {
		return nil, fmt.Errorf("failed to pack algorithm: %v", err)
	}

	// Pack COLON_BYTE (1 byte)
	if err := buf.WriteByte(COLON_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack COLON_BYTE: %v", err)
	}

	// Pack NULL_BYTE (1 byte)
	if err := buf.WriteByte(NULL_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack NULL_BYTE: %v", err)
	}

	// Pack fileHash (len(fileHash) bytes)
	if _, err := buf.Write(fileHash); err != nil {
		return nil, fmt.Errorf("failed to pack fileHash: %v", err)
	}

	return buf.Bytes(), nil
}

// Function to pack IMA path (similar to pack_ima_path in Python)
func packIMAPath(path []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Pack length (4 bytes)
	length := uint32(len(path) + 1) // length + 1 for NULL_BYTE
	if err := binary.Write(buf, binary.LittleEndian, length); err != nil {
		return nil, fmt.Errorf("failed to pack length: %v", err)
	}

	// Pack path (len(path) bytes)
	if _, err := buf.Write(path); err != nil {
		return nil, fmt.Errorf("failed to pack path: %v", err)
	}

	// Pack NULL_BYTE (1 byte)
	if err := binary.Write(buf, binary.LittleEndian, NULL_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack NULL_BYTE: %v", err)
	}
	return buf.Bytes(), nil
}

func validateIMAEntry(IMATemplateHash, depField, cgroupField, hashAlg, fileHash, filePathField string) (string, error) {
	packedDep, err := packIMAPath([]byte(depField))
	if err != nil {
		return "", fmt.Errorf("Failed to pack 'dep' field")
	}
	packedCgroup, err := packIMAPath([]byte(cgroupField))
	if err != nil {
		return "", fmt.Errorf("Failed to pack 'cgroup' field")
	}
	decodedFileHash, err := hex.DecodeString(fileHash)
	if err != nil {
		return "", fmt.Errorf("Failed to decode 'file hash' field")
	}
	packedFileHash, err := packIMAHash(hashAlg, decodedFileHash)
	if err != nil {
		return "", fmt.Errorf("Failed to pack 'file hash' field")
	}
	packedFilePath, err := packIMAPath([]byte(filePathField))
	if err != nil {
		return "", fmt.Errorf("Failed to pack 'file path' field")
	}

	IMAEntrySha1, IMAEntrySha256 := computeIMAEntryHashes(packedDep, packedCgroup, packedFileHash, packedFilePath)

	if IMAEntrySha1 != IMATemplateHash {
		return "", fmt.Errorf("computed template hash does not match stored entry template hash")
	}
	// return sha256 of entry to be extended
	return IMAEntrySha256, nil
}

func checkPodUIDMatch(path, podUID string) bool {
	var regexPattern string
	// Replace dashes in podUID with underscores
	adjustedPodUID := strings.ReplaceAll(podUID, "-", "_")
	// Regex pattern to match the pod UID in the path
	regexPattern = fmt.Sprintf(`kubepods[^\/]*-pod%s\.slice`, regexp.QuoteMeta(adjustedPodUID))

	// Compile the regex
	r, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}
	// Check if the path contains the pod UID
	return r.MatchString(path)
}

// Verify the provided signature by contacting Registrar API
func verifyWorkerSignature(workerName string, message []byte, signature string) (bool, error) {
	registrarURL := fmt.Sprintf("http://%s:%s/worker/verify", registrarHOST, registrarPORT)
	payload := map[string]string{
		"name":      workerName,
		"message":   base64.StdEncoding.EncodeToString(message),
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
		return "", "", fmt.Errorf("Failed to decode: %v", err)
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
	quoteSignatureIsValid, err := verifyWorkerSignature(workerName, quoteBytes, base64.StdEncoding.EncodeToString(sig.RSA.Signature))
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

	return hex.EncodeToString(quotePCRs.GetPcrs()[10]), quotePCRs.GetHash().String(), nil
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
	whitelistProviderWorkerValidateURL := fmt.Sprintf("http://%s:%s/whitelist/pod/image/check", whitelistHOST, whitelistPORT)

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(checkRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal Whitelist check request: %v", err)
	}

	log.Printf(string(jsonPayload))

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
	// Define the CustomResourceDefinition
	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "attestationrequests.example.com",
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "example.com",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     "AttestationRequest",
				ListKind: "AttestationRequestList",
				Plural:   "attestationrequests",
				Singular: "attestationrequest",
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name:    "v1",
					Served:  true,
					Storage: true,
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]apiextensionsv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]apiextensionsv1.JSONSchemaProps{
										"podName": {
											Type: "string",
										},
										"podUID": {
											Type: "string",
										},
										"tenantID": {
											Type: "string",
										},
										"agentName": {
											Type: "string",
										},
										"agentIP": {
											Type: "string",
										},
										"issued": {
											Type:   "string",
											Format: "date-time",
										},
										"hmac": {
											Type: "string",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Create the CRD
	attestationRequestCRD, err := apiExtensionsClient.ApiextensionsV1().CustomResourceDefinitions().Create(context.TODO(), crd, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error creating Attestation Request CRD: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	fmt.Printf(green.Sprintf("[%s] CRD '%s' created successfully\n", time.Now().Format("02-01-2006 15:04:05"), attestationRequestCRD.Name))
}

func updateAgentCRDWithAttestationResult(attestationResult *AttestationResult) {
	// Get the dynamic client resource interface for the CRD
	crdResource := dynamicClient.Resource(schema.GroupVersionResource{
		Group:    "example.com", // The group from your CRD
		Version:  "v1",          // The version of your CRD
		Resource: "agents",      // The plural resource name from your CRD
	}).Namespace("attestation-system") // Modify namespace if needed

	// Fetch the CRD instance for the given node
	crdInstance, err := crdResource.Get(context.Background(), attestationResult.Agent, metav1.GetOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error getting Agent CRD instance: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	// Get the 'spec' field of the CRD
	spec := crdInstance.Object["spec"].(map[string]interface{})

	switch attestationResult.TargetType {
	case "Node":
		spec["nodeStatus"] = attestationResult.Result
		spec["lastUpdate"] = time.Now().Format(time.RFC3339)

	case "Pod":
		// Fetch the 'podStatus' array
		podStatusList := spec["podStatus"].([]interface{})

		// Iterate through the 'podStatus' array to find and update the relevant pod
		for i, ps := range podStatusList {
			pod := ps.(map[string]interface{})
			if pod["podName"].(string) == attestationResult.Target {
				// Update pod attributes
				pod["status"] = attestationResult.Result
				pod["reason"] = attestationResult.Reason
				pod["lastCheck"] = time.Now().Format(time.RFC3339)

				// Replace the updated pod back in the podStatus array
				podStatusList[i] = pod
				break
			}
		}
		// Update the CRD spec with the modified 'podStatus' array
		spec["podStatus"] = podStatusList
		spec["lastUpdate"] = time.Now().Format(time.RFC3339)
	}

	crdInstance.Object["spec"] = spec

	// Push the updates back to the Kubernetes API
	_, err = crdResource.Update(context.Background(), crdInstance, metav1.UpdateOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error updating Agent CRD instance: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	// Log the success
	fmt.Printf(green.Sprintf("[%s] Agent CRD '%s' updated. %s: %s, Status: %s\n", time.Now().Format("02-01-2006 15:04:05"), attestationResult.Agent, attestationResult.TargetType, attestationResult.Target, attestationResult.Result))
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
