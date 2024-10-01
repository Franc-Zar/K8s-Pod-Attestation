package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/fatih/color"
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
	UUID string `json:"UUID"`
	EK   string `json:"EK"`
	AIK  string `json:"AIK"`
}

type NewWorkerResponse struct {
	Message  string `json:"message"`
	WorkerId string `json:"workerId"`
	Status   string `json:"status"`
}

type WorkerChallenge struct {
	WorkerChallenge string `json:"workerChallenge"`
}

type ChallengeResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
	HMAC    string `json:"HMAC"`
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
	agentHOST = getEnv("AGENT_HOST", "10.0.2.8")
	agentPORT = getEnv("AGENT_PORT", "30000")
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
func encryptWithEK(publicEK *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicEK, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("EK encryption failed: %v", err)
	}
	return encryptedData, nil
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

// Handle events for nodes
func handleNodeEvent(event watch.Event, node *corev1.Node) {
	switch event.Type {
	case watch.Added:
		if !nodeIsControlPlane(node) && !nodeIsRegistered(node.Name) {
			fmt.Printf(green.Sprintf("[%s] Worker node %s joined the cluster\n", time.Now().Format("02-01-2006 15:04:05"), node.Name))
			workerRegistration(node)
			createAgentCRDInstance(node.Name)
		}

	case watch.Deleted:
		if !nodeIsControlPlane(node) {
			fmt.Printf(yellow.Sprintf("[%s] Worker node %s deleted from the cluster\n", time.Now().Format("02-01-2006 15:04:05"), node.Name))
			workerRemoval(node)
			deleteAgentCRDInstance(node.Name)
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
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed to delete worker: received status code %d\n", resp.StatusCode)
		return
	}

	fmt.Printf(yellow.Sprintf("Worker Node: %s removed with success\n", node.GetName()))
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

// workerRegistration registers the worker node by calling the identification API
func workerRegistration(node *corev1.Node) {
	agentIdentifyURL := fmt.Sprintf("http://%s:%s/agent/worker/identify", agentHOST, agentPORT)
	agentChallengeNodeURL := fmt.Sprintf("http://%s:%s/agent/worker/challenge", agentHOST, agentPORT)
	registrarWorkerCreationURL := fmt.Sprintf("http://%s:%s/worker/create", registrarHOST, registrarPORT)

	err := waitForAgent(5*time.Second, 1*time.Minute)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while contacting Agent: %v\n", time.Now().Format("02-01-2006 15:04:05"), err.Error()))
	}

	// Call Agent to identify worker data
	workerData, err := callAgentIdentify(agentIdentifyURL)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to call Agent API: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	// Decode EK and AIK
	EK, err := decodePublicKeyFromPEM(workerData.EK)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to parse EK from PEM: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	AIK, err := decodePublicKeyFromPEM(workerData.AIK)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to parse AIK from PEM: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	// Calculate AIK digest
	aikDigest, err := calculateAIKDigest(AIK)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to calculate AIK digest: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	// Generate ephemeral key
	ephemeralKey, err := generateEphemeralKey(32)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to generate ephemeral key: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	// Construct worker challenge payload
	challengePayload := fmt.Sprintf("%s::%s", aikDigest, base64.StdEncoding.EncodeToString(ephemeralKey))

	// Encrypt the WorkerChallengePayload with the EK public key
	encryptedChallenge, err := encryptWithEK(EK, []byte(challengePayload))
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to encrypt challengePayload with EK: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	// Prepare challenge payload for sending
	workerChallenge := WorkerChallenge{
		WorkerChallenge: base64.StdEncoding.EncodeToString(encryptedChallenge),
	}

	// Send challenge request to the agent
	challengeResponse, err := sendChallengeRequest(agentChallengeNodeURL, workerChallenge)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to send challenge request: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	decodedHMAC, err := base64.StdEncoding.DecodeString(challengeResponse.HMAC)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to decode HMAC: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	// Verify the HMAC response from the agent
	if err := verifyHMAC([]byte(workerData.UUID), ephemeralKey, decodedHMAC); err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to verify HMAC: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
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
		return
	}

	fmt.Printf(green.Sprintf("[%s] Successfully registered Worker Node: %s\n", time.Now().Format("02-01-2006 15:04:05"), createWorkerResponse.WorkerId))
}

// Helper function to call the agent identification API
func callAgentIdentify(url string) (*WorkerResponse, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to call agent identification API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var workerResponse WorkerResponse
	if err := json.NewDecoder(resp.Body).Decode(&workerResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}
	return &workerResponse, nil
}

// Helper function to send the challenge request to the agent
func sendChallengeRequest(url string, challenge WorkerChallenge) (*ChallengeResponse, error) {
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

	// Decode the response JSON into the ChallengeResponse struct
	var challengeResponse ChallengeResponse
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
		fmt.Printf(red.Sprintf("[%s] Error creating Agent CRD instance: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
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
                agentStatus:
                  type: string
                nodeStatus:
                  type: string
                enabled:
                  type: boolean
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
