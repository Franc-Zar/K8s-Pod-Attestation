import matplotlib.pyplot as plt
import numpy as np

# Example data from the logs
kubernetes_join = """
2024-11-12 16:01:11.496, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:11.496, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:11.496, etcd, 4.2, 2.6
2024-11-12 16:01:11.663, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:11.663, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:11.663, etcd, 4.2, 2.6
2024-11-12 16:01:11.826, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:11.826, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:11.826, etcd, 4.2, 2.6
2024-11-12 16:01:11.988, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:11.988, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:11.988, etcd, 4.2, 2.6
2024-11-12 16:01:12.148, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:12.148, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:12.148, etcd, 4.2, 2.6
2024-11-12 16:01:12.312, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:12.312, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:12.312, etcd, 4.2, 2.6
2024-11-12 16:01:12.477, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:12.477, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:12.477, etcd, 4.2, 2.6
2024-11-12 16:01:12.640, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:12.640, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:12.640, etcd, 4.2, 2.6
2024-11-12 16:01:12.814, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:12.814, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:12.814, etcd, 4.2, 2.6
2024-11-12 16:01:12.979, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:12.979, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:12.979, etcd, 4.2, 2.6
2024-11-12 16:01:13.141, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:13.141, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:13.141, etcd, 4.2, 2.6
2024-11-12 16:01:13.304, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:13.304, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:13.304, etcd, 4.2, 2.6
2024-11-12 16:01:13.469, kube-apiserver, 4.2, 2.6
2024-11-12 16:01:13.469, kube-controller-manager, 0.9, 0.7
2024-11-12 16:01:13.469, etcd, 4.2, 2.6
"""

complete_registration = """
2024-11-12 18:21:15.947, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:15.947, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:15.947, etcd, 4.3, 2.6
2024-11-12 18:21:15.947, worker-handler, 0.0, 0.1
2024-11-12 18:21:15.947, registrar, 0.0, 0.1
2024-11-12 18:21:15.947, whitelist, 0.0, 0.1
2024-11-12 18:21:16.282, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:16.282, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:16.282, etcd, 4.3, 2.6
2024-11-12 18:21:16.282, worker-handler, 0.0, 0.1
2024-11-12 18:21:16.282, registrar, 0.0, 0.1
2024-11-12 18:21:16.282, whitelist, 0.0, 0.1
2024-11-12 18:21:16.615, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:16.615, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:16.615, etcd, 4.3, 2.6
2024-11-12 18:21:16.615, worker-handler, 0.0, 0.1
2024-11-12 18:21:16.615, registrar, 0.0, 0.1
2024-11-12 18:21:16.615, whitelist, 0.0, 0.1
2024-11-12 18:21:16.953, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:16.953, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:16.953, etcd, 4.3, 2.6
2024-11-12 18:21:16.953, worker-handler, 0.0, 0.1
2024-11-12 18:21:16.953, registrar, 0.0, 0.1
2024-11-12 18:21:16.953, whitelist, 0.0, 0.1
2024-11-12 18:21:17.283, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:17.283, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:17.283, etcd, 4.3, 2.6
2024-11-12 18:21:17.283, worker-handler, 0.0, 0.1
2024-11-12 18:21:17.283, registrar, 0.0, 0.1
2024-11-12 18:21:17.283, whitelist, 0.0, 0.1
2024-11-12 18:21:17.586, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:17.586, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:17.586, etcd, 4.3, 2.6
2024-11-12 18:21:17.586, worker-handler, 0.0, 0.1
2024-11-12 18:21:17.586, registrar, 0.0, 0.1
2024-11-12 18:21:17.586, whitelist, 0.0, 0.1
2024-11-12 18:21:17.916, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:17.916, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:17.916, etcd, 4.3, 2.6
2024-11-12 18:21:17.916, worker-handler, 0.0, 0.1
2024-11-12 18:21:17.916, registrar, 0.0, 0.1
2024-11-12 18:21:17.916, whitelist, 0.0, 0.1
2024-11-12 18:21:18.247, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:18.247, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:18.247, etcd, 4.3, 2.6
2024-11-12 18:21:18.247, worker-handler, 0.0, 0.1
2024-11-12 18:21:18.247, registrar, 0.0, 0.1
2024-11-12 18:21:18.247, whitelist, 0.0, 0.1
2024-11-12 18:21:18.617, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:18.617, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:18.617, etcd, 4.3, 2.6
2024-11-12 18:21:18.617, worker-handler, 0.0, 0.1
2024-11-12 18:21:18.617, registrar, 0.0, 0.1
2024-11-12 18:21:18.617, whitelist, 0.0, 0.1
2024-11-12 18:21:18.979, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:18.979, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:18.979, etcd, 4.3, 2.6
2024-11-12 18:21:18.979, worker-handler, 0.0, 0.1
2024-11-12 18:21:18.979, registrar, 0.0, 0.1
2024-11-12 18:21:18.979, whitelist, 0.0, 0.1
2024-11-12 18:21:19.302, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:19.302, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:19.302, etcd, 4.3, 2.6
2024-11-12 18:21:19.302, worker-handler, 0.0, 0.1
2024-11-12 18:21:19.302, registrar, 0.0, 0.1
2024-11-12 18:21:19.302, whitelist, 0.0, 0.1
2024-11-12 18:21:19.628, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:19.628, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:19.628, etcd, 4.3, 2.6
2024-11-12 18:21:19.628, worker-handler, 0.0, 0.1
2024-11-12 18:21:19.628, registrar, 0.0, 0.1
2024-11-12 18:21:19.628, whitelist, 0.0, 0.1
2024-11-12 18:21:19.961, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:19.961, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:19.961, etcd, 4.3, 2.6
2024-11-12 18:21:19.961, worker-handler, 0.0, 0.1
2024-11-12 18:21:19.961, registrar, 0.0, 0.1
2024-11-12 18:21:19.961, whitelist, 0.0, 0.1
2024-11-12 18:21:20.263, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:20.263, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:20.263, etcd, 4.3, 2.6
2024-11-12 18:21:20.263, worker-handler, 0.0, 0.1
2024-11-12 18:21:20.263, registrar, 0.0, 0.1
2024-11-12 18:21:20.263, whitelist, 0.0, 0.1
2024-11-12 18:21:20.623, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:20.623, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:20.623, etcd, 4.3, 2.6
2024-11-12 18:21:20.623, worker-handler, 0.0, 0.1
2024-11-12 18:21:20.623, registrar, 0.0, 0.1
2024-11-12 18:21:20.623, whitelist, 0.0, 0.1
2024-11-12 18:21:20.954, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:20.954, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:20.954, etcd, 4.3, 2.6
2024-11-12 18:21:20.954, worker-handler, 0.0, 0.1
2024-11-12 18:21:20.954, registrar, 0.0, 0.1
2024-11-12 18:21:20.954, whitelist, 0.0, 0.1
2024-11-12 18:21:21.293, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:21.293, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:21.293, etcd, 4.3, 2.6
2024-11-12 18:21:21.293, worker-handler, 0.0, 0.1
2024-11-12 18:21:21.293, registrar, 0.0, 0.1
2024-11-12 18:21:21.293, whitelist, 0.0, 0.1
2024-11-12 18:21:21.617, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:21.617, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:21.617, etcd, 4.3, 2.6
2024-11-12 18:21:21.617, worker-handler, 0.0, 0.1
2024-11-12 18:21:21.617, registrar, 0.0, 0.1
2024-11-12 18:21:21.617, whitelist, 0.0, 0.1
2024-11-12 18:21:21.948, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:21.948, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:21.948, etcd, 4.3, 2.6
2024-11-12 18:21:21.948, worker-handler, 0.0, 0.1
2024-11-12 18:21:21.948, registrar, 0.0, 0.1
2024-11-12 18:21:21.948, whitelist, 0.0, 0.1
2024-11-12 18:21:22.303, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:22.303, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:22.303, etcd, 4.3, 2.6
2024-11-12 18:21:22.303, worker-handler, 0.0, 0.1
2024-11-12 18:21:22.303, registrar, 0.0, 0.1
2024-11-12 18:21:22.303, whitelist, 0.0, 0.1
2024-11-12 18:21:22.651, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:22.651, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:22.651, etcd, 4.3, 2.6
2024-11-12 18:21:22.651, worker-handler, 0.0, 0.1
2024-11-12 18:21:22.651, registrar, 0.0, 0.1
2024-11-12 18:21:22.651, whitelist, 0.0, 0.1
2024-11-12 18:21:22.950, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:22.950, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:22.950, etcd, 4.3, 2.6
2024-11-12 18:21:22.950, worker-handler, 0.0, 0.1
2024-11-12 18:21:22.950, registrar, 0.0, 0.1
2024-11-12 18:21:22.950, whitelist, 0.0, 0.1
2024-11-12 18:21:23.284, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:23.284, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:23.284, etcd, 4.3, 2.6
2024-11-12 18:21:23.284, worker-handler, 0.0, 0.1
2024-11-12 18:21:23.284, registrar, 0.0, 0.1
2024-11-12 18:21:23.284, whitelist, 0.0, 0.1
2024-11-12 18:21:23.628, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:23.628, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:23.628, etcd, 4.3, 2.6
2024-11-12 18:21:23.628, worker-handler, 0.0, 0.1
2024-11-12 18:21:23.628, registrar, 0.0, 0.1
2024-11-12 18:21:23.628, whitelist, 0.0, 0.1
2024-11-12 18:21:24.074, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:24.074, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:24.074, etcd, 4.3, 2.6
2024-11-12 18:21:24.074, worker-handler, 0.0, 0.1
2024-11-12 18:21:24.074, registrar, 0.0, 0.1
2024-11-12 18:21:24.074, whitelist, 0.0, 0.1
2024-11-12 18:21:24.471, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:24.471, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:24.471, etcd, 4.3, 2.6
2024-11-12 18:21:24.471, worker-handler, 0.0, 0.1
2024-11-12 18:21:24.471, registrar, 0.0, 0.1
2024-11-12 18:21:24.471, whitelist, 0.0, 0.1
2024-11-12 18:21:24.864, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:24.864, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:24.864, etcd, 4.3, 2.6
2024-11-12 18:21:24.864, worker-handler, 0.0, 0.1
2024-11-12 18:21:24.864, registrar, 0.0, 0.1
2024-11-12 18:21:24.864, whitelist, 0.0, 0.1
2024-11-12 18:21:25.214, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:25.214, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:25.214, etcd, 4.3, 2.6
2024-11-12 18:21:25.214, worker-handler, 0.0, 0.1
2024-11-12 18:21:25.214, registrar, 0.0, 0.1
2024-11-12 18:21:25.214, whitelist, 0.0, 0.1
2024-11-12 18:21:25.545, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:25.545, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:25.545, etcd, 4.3, 2.6
2024-11-12 18:21:25.545, worker-handler, 0.0, 0.1
2024-11-12 18:21:25.545, registrar, 0.0, 0.1
2024-11-12 18:21:25.545, whitelist, 0.0, 0.1
2024-11-12 18:21:25.873, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:25.873, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:25.873, etcd, 4.3, 2.6
2024-11-12 18:21:25.873, worker-handler, 0.0, 0.1
2024-11-12 18:21:25.873, registrar, 0.0, 0.1
2024-11-12 18:21:25.873, whitelist, 0.0, 0.1
2024-11-12 18:21:26.171, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:26.171, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:26.171, etcd, 4.3, 2.6
2024-11-12 18:21:26.171, worker-handler, 0.0, 0.1
2024-11-12 18:21:26.171, registrar, 0.0, 0.1
2024-11-12 18:21:26.171, whitelist, 0.0, 0.1
2024-11-12 18:21:26.469, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:26.469, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:26.469, etcd, 4.3, 2.6
2024-11-12 18:21:26.469, worker-handler, 0.0, 0.1
2024-11-12 18:21:26.469, registrar, 0.0, 0.1
2024-11-12 18:21:26.469, whitelist, 0.0, 0.1
2024-11-12 18:21:26.774, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:26.774, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:26.774, etcd, 4.3, 2.6
2024-11-12 18:21:26.774, worker-handler, 0.0, 0.1
2024-11-12 18:21:26.774, registrar, 0.0, 0.1
2024-11-12 18:21:26.774, whitelist, 0.0, 0.1
2024-11-12 18:21:27.080, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:27.080, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:27.080, etcd, 4.3, 2.6
2024-11-12 18:21:27.080, worker-handler, 0.0, 0.1
2024-11-12 18:21:27.080, registrar, 0.0, 0.1
2024-11-12 18:21:27.080, whitelist, 0.0, 0.1
2024-11-12 18:21:27.361, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:27.361, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:27.361, etcd, 4.3, 2.6
2024-11-12 18:21:27.361, worker-handler, 0.0, 0.1
2024-11-12 18:21:27.361, registrar, 0.0, 0.1
2024-11-12 18:21:27.361, whitelist, 0.0, 0.1
2024-11-12 18:21:27.644, kube-apiserver, 4.3, 2.6
2024-11-12 18:21:27.644, kube-controller-manager, 0.9, 0.7
2024-11-12 18:21:27.644, etcd, 4.3, 2.6
2024-11-12 18:21:27.644, worker-handler, 0.0, 0.1
2024-11-12 18:21:27.644, registrar, 0.0, 0.1
2024-11-12 18:21:27.644, whitelist, 0.0, 0.1
"""

# Parse the data
cpu_kubernetes = []
mem_kubernetes = []

# Split the data by lines and process each line
for line in kubernetes_join.strip().split("\n"):
    _, process, cpu, mem = line.split(", ")
    
    # Sum CPU and Memory usage for the "Kubernetes" process (sum of all components)
    if process in ["kube-apiserver", "kube-controller-manager", "etcd"]:
        cpu_kubernetes.append(float(cpu))
        mem_kubernetes.append(float(mem))

# Sum the CPU and Memory usage for the "Kubernetes" process
cpu_kubernetes_sum = np.array(cpu_kubernetes).reshape(-1, 3).sum(axis=1)
mem_kubernetes_sum = np.array(mem_kubernetes).reshape(-1, 3).sum(axis=1)

# Generate elapsed time based on 0.1s intervals, but only once per group of 3 lines
num_snapshots = len(cpu_kubernetes_sum)
elapsed_time = np.arange(0, num_snapshots * 0.1, 0.1)  # in seconds

# Create the plot for CPU usage
fig, ax1 = plt.subplots(figsize=(18, 10))
ax1.plot(elapsed_time, cpu_kubernetes_sum, label="Kubernetes CPU Usage (%)", color="blue", marker="o")
ax1.set_xlabel("Elapsed Time (s)")
ax1.set_ylabel("CPU Usage (%)")
ax1.set_title("Kubernetes Control-Plane CPU Usage Over Time")
ax1.legend(loc="upper left")

# Save the CPU plot to a PDF
plt.tight_layout()
plt.savefig("kubernetes_cpu_usage.pdf")
plt.show()

# Create the plot for Memory usage
fig, ax2 = plt.subplots(figsize=(18, 10))
ax2.plot(elapsed_time, mem_kubernetes_sum, label="Kubernetes Memory Usage (%)", color="green", marker="o")
ax2.set_xlabel("Elapsed Time (s)")
ax2.set_ylabel("Memory Usage (%)")
ax2.set_title("Kubernetes Control-Plane Memory Usage Over Time")
ax2.legend(loc="upper left")

# Save the Memory plot to a PDF
plt.tight_layout()
plt.savefig("kubernetes_memory_usage.pdf")
plt.show()
