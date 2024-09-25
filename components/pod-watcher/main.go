package main

import (
	"context"
	"fmt"
	"github.com/fatih/color"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/homedir"
	"os"
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

// Global Kubernetes clientset variable
var clientset *kubernetes.Clientset
var dynamicClient dynamic.Interface

var attestationNamespace string

var (
	red    *color.Color
	green  *color.Color
	yellow *color.Color
)

func main() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)

	var err error
	// Initialize Kubernetes client
	clientset, dynamicClient, err = getKubernetesClient()
	if err != nil {
		panic(err)
	}

	attestationNamespace = os.Getenv("attestation_namespace")
	if attestationNamespace == "" {
		fmt.Printf(yellow.Sprintf("[%s] 'attestation_namespace' environment variable missing: setting 'default' value\n", time.Now().Format("02-01-2006 15:04:05")))
		attestationNamespace = "default"
	}

	// Watch for node events
	watchPods()
}

func getTenantIDFromPodName(podName string) string {

	parts := strings.Split(podName, "-tenant-")

	// The tenantID is the last part of the split array
	tenantID := parts[len(parts)-1]
	return tenantID
}

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

func watchPods() {
	fmt.Println(green.Sprintln("Watching Pod changes..."))

	watcher, err := clientset.CoreV1().Pods(attestationNamespace).Watch(context.Background(), v1.ListOptions{})
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

			nodeName := pod.Spec.NodeName
			if nodeName == "" || strings.Contains(pod.Name, "agent") {
				continue
			}

			switch event.Type {
			case watch.Added:
				fmt.Printf(green.Sprintf("[%s] Pod %s added to node %s\n", time.Now().Format("02-01-2006 15:04:05"), pod.Name, nodeName))
				updateAgentCRDWithPodStatus(nodeName, pod.Name, "Trusted")

			case watch.Deleted:
				fmt.Printf(yellow.Sprintf("[%s] Pod %s deleted from node %s\n", time.Now().Format("02-01-2006 15:04:05"), pod.Name, nodeName))
				updateAgentCRDWithPodStatus(nodeName, pod.Name, "Deleted")
			}
		}
	}
}

func updateAgentCRDWithPodStatus(nodeName, podName, status string) {
	// Get the current CRD instance
	crdResource := dynamicClient.Resource(schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "agents",
	}).Namespace("kube-system")
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

	if status != "Deleted" {
		newPodStatus = append(newPodStatus, map[string]interface{}{
			"podName":   podName,
			"tenantID":  getTenantIDFromPodName(podName),
			"status":    status,
			"reason":    "reason of new status",
			"lastCheck": time.Now().Format("2006-01-02T15:04:05Z07:00"),
		})
	}

	spec["podStatus"] = newPodStatus

	crdInstance.Object["spec"] = spec

	// Update the CRD instance
	_, err = crdResource.Update(context.Background(), crdInstance, v1.UpdateOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("Error updating Agent CRD instance: %v\n", err))
		return
	}

	fmt.Printf(green.Sprintf("[%s] Agent CRD 'agent-%s' updated. Involved Pod: %s\n", time.Now().Format("02-01-2006 15:04:05"), nodeName, podName))
}
