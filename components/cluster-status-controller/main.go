package main

import (
	"context"
	"fmt"
	"github.com/fatih/color"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	red           *color.Color
	green         *color.Color
	yellow        *color.Color
	blue          *color.Color
	dynamicClient dynamic.Interface
	clientset     *kubernetes.Clientset
)

func initializeColors() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
	blue = color.New(color.FgBlue)
}

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
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

func watchAgentCRDChanges(stopCh chan os.Signal) {
	// Define the GVR (GroupVersionResource) for the CRD you want to watch
	crdGVR := schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "agents",
	}

	// Start watching for changes to the CRD
	watcher, err := dynamicClient.Resource(crdGVR).Namespace("attestation-system").Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}
	defer watcher.Stop()

	// Process events from the watcher
	for {
		select {
		case event := <-watcher.ResultChan():
			switch event.Type {
			case watch.Added:
				fmt.Printf(green.Sprintf("[%s] Agent CRD Added:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatAgentCRD(event.Object)))
			case watch.Modified:
				fmt.Printf(blue.Sprintf("[%s] Agent CRD Modified:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatAgentCRD(event.Object)))
				checkAgentStatus(event.Object)
			case watch.Deleted:
				fmt.Printf(yellow.Sprintf("[%s] Agent CRD Deleted:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatAgentCRD(event.Object)))
			case watch.Error:
				fmt.Printf(red.Sprintf("[%s] Error:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatAgentCRD(event.Object)))
			}
		case <-stopCh:
			return
		}
	}
}

func formatAgentCRD(obj interface{}) map[string]interface{} {
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

func deletePod(podName string) error {
	// Get all pods
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", podName),
	})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while searching for Pod: %s: %v", time.Now().Format("02-01-2006 15:04:05"), podName, err))
		return err
	}

	// Delete each pod on the node
	for _, pod := range pods.Items {
		err := clientset.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
		if err != nil {
			fmt.Printf(red.Sprintf("[%s] Error deleting Pod %s in namespace %s: %v", time.Now().Format("02-01-2006 15:04:05"), pod.Name, pod.Namespace, err))
			return err
		}
	}

	fmt.Printf(yellow.Sprintf("[%s] Deleted untrusted Pod %s from trusted node\n", time.Now().Format("02-01-2006 15:04:05"), podName))
	return nil
}

func deleteAllPodsFromNode(nodeName string) {
	// Get all pods on the specified node
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error listing pods on node %s: %v", time.Now().Format("02-01-2006 15:04:05"), nodeName, err))
		return
	}

	// Delete each pod on the node
	for _, pod := range pods.Items {
		err := clientset.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
		if err != nil {
			fmt.Printf(red.Sprintf("[%s] Error deleting pod %s in namespace %s: %v", time.Now().Format("02-01-2006 15:04:05"), pod.Name, pod.Namespace, err))
			return
		}
		fmt.Printf(yellow.Sprintf("[%s] Deleted pod %s from untrusted node %s\n", time.Now().Format("02-01-2006 15:04:05"), pod.Name, nodeName))
	}

	fmt.Printf(yellow.Sprintf("[%s] Deleted all pods from untrusted node %s\n", time.Now().Format("02-01-2006 15:04:05"), nodeName))
}

func deleteNode(nodeName string) {
	// Delete the node
	err := clientset.CoreV1().Nodes().Delete(context.TODO(), nodeName, metav1.DeleteOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error deleting Node %s: %v\n", time.Now().Format("02-01-2006 15:04:05"), nodeName, err))
		return
	}

	fmt.Printf(yellow.Sprintf("[%s] Deleted untrusted node %s\n", time.Now().Format("02-01-2006 15:04:05"), nodeName))
	return
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

func checkAgentStatus(obj interface{}) {
	spec := formatAgentCRD(obj)

	if spec["nodeStatus"] == "UNTRUSTED" {
		nodeName, err := extractNodeName(spec["agentName"].(string))
		if err != nil {
			fmt.Printf(red.Sprintf("[%s] Error: 'agentName': %s syntax is not valid", time.Now().Format("02-01-2006 15:04:05"), spec["agentName"]))
			return
		}
		deleteAllPodsFromNode(nodeName)
		deleteNode(nodeName)
		return
	}

	podStatusInterface, exists := spec["podStatus"]
	if !exists {
		fmt.Printf(red.Sprintf("[%s] Error: Missing 'podStatus' field in Agent CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	podStatus, ok := podStatusInterface.([]interface{})
	if !ok {
		fmt.Printf(red.Sprintf("[%s] Error: Unable to parse 'podStatus' field in Agent CRD\n", time.Now().Format("02-01-2006 15:04:05")))
		return
	}

	for _, ps := range podStatus {
		pod := ps.(map[string]interface{})
		podName, ok := pod["podName"].(string)
		if !ok {
			fmt.Printf(red.Sprintf("[%s] Error: Unable to parse 'podName' field in 'podStatus'\n", time.Now().Format("02-01-2006 15:04:05")))
			continue
		}
		status, ok := pod["status"].(string)
		if !ok {
			fmt.Printf(red.Sprintf("[%s] Error: Unable to parse 'status' field in 'podStatus'\n", time.Now().Format("02-01-2006 15:04:05")))
			continue
		}

		if status == "UNTRUSTED" {
			fmt.Printf(yellow.Sprintf("[%s] Detected Untrusted Pod: %s\n", time.Now().Format("02-01-2006 15:04:05"), podName))
			err := deletePod(podName)
			if err != nil {
				fmt.Printf(red.Sprintf("[%s] Error deleting pod: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
			}
			fmt.Printf(yellow.Sprintf("[%s] Untrusted Pod: %s deleted\n", time.Now().Format("02-01-2006 15:04:05"), podName))
		}
	}
}

func main() {
	initializeColors()
	configureKubernetesClient()

	stopCh := setupSignalHandler()

	watchAgentCRDChanges(stopCh)

	// Keep the application running until terminated
	fmt.Printf(green.Sprintf("Watching Agent CRD changes...\n\n"))
	<-stopCh
}
