package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/homedir"
	"log"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Global Kubernetes clientset variable
var clientset *kubernetes.Clientset
var dynamicClient dynamic.Interface

var attestationNamespaces string
var attestationEnabledNamespaces []string

var (
	red    *color.Color
	green  *color.Color
	yellow *color.Color
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	attestationNamespaces = getEnv("ATTESTATION_NAMESPACES", "[\"default\"]")
	// setting namespaces allowed for attestation: only pods deployed  be attested
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

// isNamespaceEnabledForAttestation checks if the given podNamespace is enabled for attestation.
func isNamespaceEnabledForAttestation(podNamespace string) bool {
	for _, ns := range attestationEnabledNamespaces {
		if ns == podNamespace {
			return true
		}
	}
	return false
}

// initializeColors sets up color variables for console output.
func initializeColors() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
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

// Check if Node being considered is Control Plane
func nodeIsControlPlane(nodeName string) bool {
	// Get the node object to check for control plane label
	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, v1.GetOptions{})
	if err != nil {
		return false
	}

	// Check if the node is a control plane node
	_, exists := node.Labels["node-role.kubernetes.io/control-plane"]
	return exists
}

func watchPods() {
	fmt.Println(green.Sprintln("Watching Pod changes..."))

	watcher, err := clientset.CoreV1().Pods("").Watch(context.Background(), v1.ListOptions{})
	if err != nil {
		panic(err)
	}
	defer watcher.Stop()

	for {
		select {
		case event := <-watcher.ResultChan():
			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				continue
			}

			podNamespace := pod.GetNamespace()
			nodeName := pod.Spec.NodeName
			if !isNamespaceEnabledForAttestation(podNamespace) || nodeIsControlPlane(nodeName) {
				continue
			}

			switch event.Type {
			case watch.Added:
				fmt.Printf(green.Sprintf("[%s] Pod %s added to node '%s'\n", time.Now().Format("02-01-2006 15:04:05"), pod.Name, nodeName))
				updateAgentCRDWithPodStatus(nodeName, pod.Name, pod.Annotations["tenantID"], "TRUSTED")

			case watch.Deleted:
				fmt.Printf(yellow.Sprintf("[%s] Pod %s deleted from node %s\n", time.Now().Format("02-01-2006 15:04:05"), pod.Name, nodeName))
				updateAgentCRDWithPodStatus(nodeName, pod.Name, pod.Annotations["tenantID"], "DELETED")
			}
		}
	}
}

func updateAgentCRDWithPodStatus(nodeName, podName, tenantId, status string) {
	// Get the current CRD instance
	crdResource := dynamicClient.Resource(schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "agents",
	}).Namespace("attestation-system")
	crdInstance, err := crdResource.Get(context.Background(), "agent-"+nodeName, v1.GetOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("Error getting Agent CRD instance: %v\n", err))
		return
	}

	// Initialize 'podStatus' as an empty slice of interfaces if it's nil
	spec := crdInstance.Object["spec"].(map[string]interface{})
	podStatus := spec["podStatus"]
	if podStatus == nil {
		spec["podStatus"] = make([]interface{}, 0)
	}

	// Update the pod status in the CRD
	newPodStatus := make([]interface{}, 0)

	for _, ps := range spec["podStatus"].([]interface{}) {
		pod := ps.(map[string]interface{})
		if pod["podName"].(string) != podName {
			newPodStatus = append(newPodStatus, ps)
		}
	}

	if status != "DELETED" {
		newPodStatus = append(newPodStatus, map[string]interface{}{
			"podName":   podName,
			"tenantID":  tenantId,
			"status":    status,
			"reason":    "Pod just created",
			"lastCheck": time.Now().Format(time.RFC3339),
		})
	}

	spec["podStatus"] = newPodStatus
	spec["lastUpdate"] = time.Now().Format(time.RFC3339)
	crdInstance.Object["spec"] = spec

	// Update the CRD instance
	_, err = crdResource.Update(context.Background(), crdInstance, v1.UpdateOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("Error updating Agent CRD instance: %v\n", err))
		return
	}

	fmt.Printf(green.Sprintf("[%s] Agent CRD 'agent-%s' updated. Involved Pod: %s\n", time.Now().Format("02-01-2006 15:04:05"), nodeName, podName))
}

func main() {
	initializeColors()
	configureKubernetesClient()
	loadEnvironmentVariables()

	// Watch for Pod events
	watchPods()
}
