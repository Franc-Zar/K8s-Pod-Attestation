package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	Status   string `json:"status"`
}

// Global variables
var (
	clientset      *kubernetes.Clientset
	dynamicClient  dynamic.Interface
	red, green, _  = color.New(color.FgRed), color.New(color.FgGreen), color.New(color.FgYellow)
	registrarHOST  = os.Getenv("REGISTRAR_HOST")
	registrarPORT  = os.Getenv("REGISTRAR_PORT")
	podHandlerPORT = os.Getenv("POD_HANDLER_PORT")
)

// Helper to verify environment variables
func verifyEnvVars() {
	if registrarHOST == "" || registrarPORT == "" || podHandlerPORT == "" {
		registrarHOST = "localhost"
		registrarPORT = "8080"
		podHandlerPORT = "8081"
		//log.Fatal("One or more environment variables (REGISTRAR_HOST, REGISTRAR_PORT, POD_HANDLER_PORT) are not set")
	}
}

// Secure Pod Deployment Handler
func securePodDeployment(c *gin.Context) {
	var req DeploymentRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request format"})
		return
	}

	// Verify the signature by calling the Registrar API
	isValid, err := verifyManifestSignature(req.TenantName, req.Manifest, req.Signature)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Error contacting Registrar"})
		return
	}

	if isValid {
		if err := deployPod(req.Manifest, req.TenantName); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to deploy Pod"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Pod successfully deployed"})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Invalid signature"})
	}
}

// Verify the manifest signature by contacting Registrar API
func verifyManifestSignature(tenantName, manifest, signature string) (bool, error) {
	registrarURL := fmt.Sprintf("http://%s:%s/tenant/verify", registrarHOST, registrarPORT)
	payload := map[string]string{
		"name":      tenantName,
		"message":   manifest,
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

// Get Kubernetes Client
func getKubernetesClient() (*kubernetes.Clientset, dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, nil, err
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	return clientset, dynamicClient, nil
}

// Deploy a Pod using the Kubernetes client
func deployPod(yamlContent, tenantName string) error {
	clientset, _, err := getKubernetesClient()
	if err != nil {
		return fmt.Errorf("failed to get Kubernetes client: %v", err)
	}

	tenantResp, err := getTenantInfo(tenantName)
	if err != nil {
		return err
	}

	var pod v1.Pod
	if err := yaml.Unmarshal([]byte(yamlContent), &pod); err != nil {
		return fmt.Errorf("failed to unmarshal YAML: %v", err)
	}

	if pod.Namespace == "" {
		pod.Namespace = "default"
	}

	pod.ObjectMeta.Name = fmt.Sprintf("%s-tenant-%s", pod.GetObjectMeta().GetName(), tenantResp.TenantID)
	podsClient := clientset.CoreV1().Pods(pod.Namespace)
	result, err := podsClient.Create(context.TODO(), &pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Pod: %v", err)
	}

	fmt.Printf(green.Sprintf("Pod %s created successfully in namespace %s\n", result.GetObjectMeta().GetName(), result.GetNamespace()))
	return nil
}

// Get Tenant Info from Registrar
func getTenantInfo(tenantName string) (*Tenant, error) {
	registrarURL := fmt.Sprintf("http://%s:%s/tenant/getByName?name=%s", registrarHOST, registrarPORT, tenantName)
	resp, err := http.Get(registrarURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve Tenant info: %v", err)
	}
	defer resp.Body.Close()

	var tenantResp Tenant
	if err := json.NewDecoder(resp.Body).Decode(&tenantResp); err != nil {
		return nil, fmt.Errorf("failed to parse Tenant response: %v", err)
	}
	return &tenantResp, nil
}

func main() {
	verifyEnvVars()

	r := gin.Default()
	r.POST("/pod/deploy", securePodDeployment)

	fmt.Printf(green.Sprintf("Pod Handler is running on port %s...\n", podHandlerPORT))
	if err := r.Run(":" + podHandlerPORT); err != nil {
		log.Fatal(err)
	}
}
