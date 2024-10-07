package main

import (
	"bytes"
	"context"
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
	Nonce    string `json:"nonce"`
	PodName  string `json:"podName"`
	PodUID   string `json:"podUID"`
	TenantId string `json:"tenantId"`
}

type AttestationResponse struct {
	Evidence  Evidence `json:"evidence"`
	Signature string   `json:"signature,omitempty"`
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
	_, err = verifyAttestationSignature(workerName, string(evidenceJSON), attestationResponse.Signature)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Evidence Signature Verification failed: %s\n", time.Now().Format("02-01-2006 15:04:05"), err.Error()))
		return
	}

	if attestationResponse.Evidence.Nonce != nonce {
		fmt.Printf(red.Sprintf("[%s] Nonce match verification failed\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	fmt.Printf(green.Sprintf("[%s] Received valid Attestation Response: %s\n", time.Now().Format("02-01-2006 15:04:05"), attestationResponse.Evidence))
	return
}

// Verify the provided signature by contacting Registrar API
func verifyAttestationSignature(workerName, evidence, signature string) (bool, error) {
	registrarURL := fmt.Sprintf("http://%s:%s/worker/verify", registrarHOST, registrarPORT)
	payload := map[string]string{
		"name":      workerName,
		"message":   evidence,
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
