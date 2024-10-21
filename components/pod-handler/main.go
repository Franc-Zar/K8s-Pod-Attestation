package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sigs.k8s.io/yaml"
	"time"
)

// Structs for request/response
type DeploymentRequest struct {
	TenantName string `json:"tenantName"`
	Manifest   string `json:"manifest"`
	Signature  string `json:"signature"`
}

type RegistrarResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

type Tenant struct {
	TenantID string `json:"tenantID"`
}

type AttestationRequest struct {
	TenantName string `json:"tenantName"`
	PodName    string `json:"podName"`
	Signature  string `json:"signature"`
}

// Global variables
var (
	red                          *color.Color
	green                        *color.Color
	yellow                       *color.Color
	clientset                    *kubernetes.Clientset
	dynamicClient                dynamic.Interface
	registrarHOST                string
	registrarPORT                string
	podHandlerPORT               string
	attestationNamespaces        string
	attestationEnabledNamespaces []string
	//attestation secret is shared between Pod Handler and Verifier to avoid issuance of unauthentic attestation requests
	attestationSecret = []byte("this_is_a_32_byte_long_secret_k")
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	registrarHOST = getEnv("REGISTRAR_HOST", "localhost")
	registrarPORT = getEnv("REGISTRAR_PORT", "8080")
	podHandlerPORT = getEnv("POD_HANDLER_PORT", "8081")
	attestationNamespaces = getEnv("ATTESTATION_NAMESPACES", "[\"default\"]")

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

// initializeColors sets up color variables for console output.
func initializeColors() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
}

// isNamespaceEnabledForAttestation checks if the given podNamespace is enabled for attestation.
func isNamespaceEnabledForAttestation(podNamespace string) bool {
	for _, ns := range attestationEnabledNamespaces {
		if ns == podNamespace {
			return true
		}
	}
	return false
}

// Secure Pod Deployment Handler
func securePodDeployment(c *gin.Context) {
	var req DeploymentRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request format"})
		return
	}

	// Verify the signature by calling the Registrar API
	isValid, err := verifyTenantSignature(req.TenantName, req.Manifest, req.Signature)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Error contacting Registrar"})
		return
	}

	if isValid {
		if err := deployPod(req.Manifest, req.TenantName); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": fmt.Sprintf("Failed to deploy Pod: %v", err.Error())})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Pod successfully deployed"})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Invalid signature over provided Pod Manifest"})
	}
}

// Verify the provided signature by contacting Registrar API
func verifyTenantSignature(tenantName, message, signature string) (bool, error) {
	registrarURL := fmt.Sprintf("http://%s:%s/tenant/verify", registrarHOST, registrarPORT)
	payload := map[string]string{
		"name":      tenantName,
		"message":   message,
		"signature": signature,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	resp, err := http.Post(registrarURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Registrar API returned status: %v", resp.Status)
	}

	var registrarResp RegistrarResponse
	if err := json.NewDecoder(resp.Body).Decode(&registrarResp); err != nil {
		return false, err
	}

	return registrarResp.Status == "success" && registrarResp.Message == "Signature verification successful", nil
}

func getAttestationInformation(podName string) (string, string, string, error) {
	// Retrieve the Pod from the Kubernetes API
	pod, err := clientset.CoreV1().Pods("").Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to retrieve Pod: %v", err.Error())
	}

	// Check if the pod is in a Running state
	if pod.Status.Phase != v1.PodRunning {
		return "", "", "", fmt.Errorf("Pod: %s is not running", podName)
	}

	podUID := pod.GetUID()
	nodeName := pod.Spec.NodeName

	// Retrieve the Node information using the nodeName
	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to retrieve node: %v", err.Error())
	}

	// Loop through the addresses of the node to find the InternalIP (within the cluster)
	var agentIP string
	for _, address := range node.Status.Addresses {
		if address.Type == v1.NodeInternalIP {
			agentIP = address.Address
			break
		}
	}

	if agentIP == "" {
		return "", "", "", fmt.Errorf("no internal IP found for node: %s", nodeName)
	}

	return nodeName, agentIP, string(podUID), nil
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

// Deploy a Pod using the Kubernetes client
func deployPod(yamlContent, tenantName string) error {
	tenantResp, err := getTenantInfo(tenantName)
	if err != nil {
		return err
	}

	var pod v1.Pod
	if err := yaml.Unmarshal([]byte(yamlContent), &pod); err != nil {
		return fmt.Errorf("failed to unmarshal YAML: %v", err.Error())
	}

	if !isNamespaceEnabledForAttestation(pod.Namespace) {
		return fmt.Errorf("failed to create Pod: provided Pod Namespace: '%s' is not included in namespaces enabled for attestation: %s", pod.Namespace, attestationEnabledNamespaces)
	}

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	pod.Annotations["tenantID"] = tenantResp.TenantID

	podsClient := clientset.CoreV1().Pods(pod.Namespace)
	result, err := podsClient.Create(context.TODO(), &pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Pod: %v", err.Error())
	}

	fmt.Printf(green.Sprintf("[%s] Pod '%s' created successfully in namespace '%s': deployed on Worker node '%s'\n", time.Now().Format("02-01-2006 15:04:05"), result.GetObjectMeta().GetName(), result.GetNamespace(), result.Spec.NodeName))
	return nil
}

// Get Tenant Info from Registrar
func getTenantInfo(tenantName string) (*Tenant, error) {
	registrarURL := fmt.Sprintf("http://%s:%s/tenant/getIdByName?name=%s", registrarHOST, registrarPORT, tenantName)
	resp, err := http.Get(registrarURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve Tenant info: %v", err.Error())
	}
	defer resp.Body.Close()

	var tenantResp Tenant
	if err := json.NewDecoder(resp.Body).Decode(&tenantResp); err != nil {
		return nil, fmt.Errorf("failed to parse Tenant response: %v", err.Error())
	}
	return &tenantResp, nil
}

func issueAttestationRequestCRD(podName, podUID, tenantId, agentName, agentIP, hmac string) error {
	// Define the GroupVersionResource (GVR) for your CRD
	gvr := schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "attestationrequests", // plural name of the CRD
	}

	// Create an unstructured object to represent the AttestationRequest
	attestationRequest := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "example.com/v1",
			"kind":       "AttestationRequest",
			"metadata": map[string]interface{}{
				"name": fmt.Sprintf("attestation-request-%s", podName), // Unique name for the custom resource
			},
			"spec": map[string]interface{}{
				"podName":   podName,
				"podUID":    podUID,
				"tenantID":  tenantId,
				"agentName": agentName,
				"agentIP":   agentIP,
				"issued":    time.Now().Format(time.RFC3339), // Current timestamp in RFC3339 format
				"hmac":      hmac,
			},
		},
	}

	// Create the AttestationRequest CR in the attestation namespace
	_, err := dynamicClient.Resource(gvr).Namespace("attestation-system").Create(context.TODO(), attestationRequest, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to create AttestationRequest: %v", time.Now().Format("02-01-2006 15:04:05"), err.Error()))
		return err
	}

	fmt.Printf(green.Sprintf("[%s] AttestationRequest for Pod: %s created successfully\n", time.Now().Format("02-01-2006 15:04:05"), podName))
	return nil
}

func requestPodAttestation(c *gin.Context) {
	var req AttestationRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request format"})
		return
	}

	// Verify the signature by calling the Registrar API
	isValid, err := verifyTenantSignature(req.TenantName, req.PodName, req.Signature)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Error contacting Registrar"})
		return
	}

	if !isValid {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Invalid Signature "})
		return
	}

	tenant, err := getTenantInfo(req.TenantName)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Failed to retrieve Tenant info"})
		return
	}

	// get Pod information (Worker on which it is deployed, this is needed to also retrieve the Agent to contact, the Agent CRD to control ensuring Tenant ownership of pod to be attested)
	workerDeploying, agentIP, podUID, err := getAttestationInformation(req.PodName)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": err.Error()})
		return
	}

	agentCRDName := fmt.Sprintf("agent-%s", workerDeploying)

	// check if Pod is signed into the target Agent CRD and if it is actually owned by the calling Tenant
	err = checkAgentCRD(agentCRDName, req.PodName, tenant.TenantID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": err.Error()})
		return
	}

	integrityMessage := fmt.Sprintf("%s::%s::%s::%s::%s", req.PodName, podUID, tenant.TenantID, agentCRDName, agentIP)
	hmacValue, err := computeHMAC([]byte(integrityMessage), attestationSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "HMAC computation failed",
		})
		return
	}

	// issue an Attestation Request for target Pod and Agent, it will be intercepted by the Verifier
	err = issueAttestationRequestCRD(req.PodName, podUID, tenant.TenantID, agentCRDName, agentIP, base64.StdEncoding.EncodeToString(hmacValue))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"status": "success", "message": "Attestation Request issued with success"})
	return
}

// Helper function to compute HMAC using the ephemeral key
func computeHMAC(message, key []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil), nil
}

func checkAgentCRD(agentCRDName, podName, tenantId string) error {
	// Define the GVR (GroupVersionResource) for the CRD you want to watch
	crdGVR := schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "agents",
	}

	// Use the dynamic client to get the CRD by name
	crd, err := dynamicClient.Resource(crdGVR).Namespace("attestation-system").Get(context.TODO(), agentCRDName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to retrieve Agent CRD: %v", err.Error())
	}

	// Example: Access a specific field in the spec (assuming CRD has a "spec" field)
	if podStatus, found, err := unstructured.NestedSlice(crd.Object, "spec", "podStatus"); found && err == nil {
		for _, ps := range podStatus {
			pod := ps.(map[string]interface{})
			// check if Pod belongs to calling Tenant
			if pod["podName"].(string) == podName && pod["tenantID"].(string) == tenantId {
				return nil
			}
		}
	} else if err != nil {
		return fmt.Errorf("error retrieving podStatus")
	} else {
		return fmt.Errorf("podStatus field not found")
	}
	return fmt.Errorf("failed to retrieve requested Pod: %s in the Agent CRD: %s", podName, agentCRDName)
}

func main() {
	initializeColors()
	loadEnvironmentVariables()
	configureKubernetesClient()

	r := gin.Default()
	r.POST("/pod/deploy", securePodDeployment)
	r.POST("/pod/attest", requestPodAttestation)

	fmt.Printf(green.Sprintf("Pod-Handler is running on port %s...\n", podHandlerPORT))
	if err := r.Run(":" + podHandlerPORT); err != nil {
		log.Fatal(err.Error())
	}
}
