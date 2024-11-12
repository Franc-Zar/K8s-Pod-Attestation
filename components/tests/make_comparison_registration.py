import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta

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

def parse_log(log):
    data = []
    for line in log.strip().split('\n'):
        parts = line.split(', ')
        timestamp = datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S.%f")
        cpu = float(parts[2])
        memory = float(parts[3])
        data.append((timestamp, cpu, memory))
    return data

def aggregate_data(data, interval=0.1):
    # Create an interval starting from the first timestamp
    start_time = data[0][0]
    aggregated = defaultdict(lambda: {'cpu': 0, 'memory': 0})
    
    # Iterate over data and aggregate CPU and Memory values
    for timestamp, cpu, memory in data:
        # Calculate time difference in seconds and round to the nearest interval
        delta = (timestamp - start_time).total_seconds()
        interval_key = round(delta / interval) * interval
        aggregated[interval_key]['cpu'] += cpu
        aggregated[interval_key]['memory'] += memory
    
    # Sort by time intervals
    times = sorted(aggregated.keys())
    cpu_values = [aggregated[time]['cpu'] for time in times]
    memory_values = [aggregated[time]['memory'] for time in times]
    
    return times, cpu_values, memory_values

# Parse the logs
kubernetes_data = parse_log(kubernetes_join)
registration_data = parse_log(complete_registration)

# Aggregate data
join_times, join_cpu, join_memory = aggregate_data(kubernetes_data)
reg_times, reg_cpu, reg_memory = aggregate_data(registration_data)

# Plotting the comparison for CPU and Memory

# CPU Usage Plot
plt.figure(figsize=(9, 5))
plt.plot(join_times, join_cpu, label='Kubernetes Join', color='b', marker='o')
plt.plot(reg_times, reg_cpu, label='Worker Registration', color='r', marker="^")
plt.xlabel('Time (s)')
plt.ylabel('CPU Usage (%)')
plt.legend()
plt.xticks(np.arange(0, 13, 1))
plt.yticks(np.arange(8.75, 10, 0.25))
plt.tight_layout()
plt.grid()
plt.savefig('registration_cpu_comparison.pdf')

# Memory Usage Plot
plt.figure(figsize=(9, 5))
plt.plot(join_times, join_memory, label='Kubernetes Join', color='b', marker='o')
plt.plot(reg_times, reg_memory, label='Worker Registration', color='r', marker="^")
plt.xlabel('Time (s)')
plt.ylabel('Memory Usage (%)')
plt.legend()
plt.xticks(np.arange(0, 13, 1))
plt.yticks(np.arange(5, 7, 0.25))
plt.tight_layout()
plt.grid()
plt.savefig('registration_memory_comparison.pdf')

