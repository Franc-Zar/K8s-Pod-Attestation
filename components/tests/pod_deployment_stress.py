import matplotlib.pyplot as plt
import numpy as np
from matplotlib import rcParams

rcParams['font.weight'] = 'bold'

# Example data (replace these with your actual start and end times)
num_pods_list = [20, 40, 60, 80, 100]  # Example number of pods
start_times_deployment = [15.371, 30.856, 37.558, 16.006, 20.804]  # Start times in seconds
end_times_deployment = [18.214, 37.876, 48.566, 30.726, 41.422]  # End times in seconds

################################################################
start_times_kubernetes = [35.332, 7.929, 0.378, 30.06, 34.582]
end_times_kubernetes = [35.759, 8.777, 1.697, 31.691, 36.95]
 

# Calculate time intervals (end_time - start_time)
deployment_times = [end - start for start, end in zip(start_times_deployment, end_times_deployment)]
kubernetes_times = [end - start for start, end in zip(start_times_kubernetes, end_times_kubernetes)]

# Plotting the results
plt.figure(figsize=(9, 5))
plt.plot(num_pods_list, kubernetes_times, label='Kubernetes Deployment', marker='o', color='b')
plt.plot(num_pods_list, deployment_times, label='Secure Pod Deployment', marker='^', color='r')
plt.xlabel('Number of Pods', weight='bold')
plt.ylabel('Time (s)', weight='bold')
plt.yticks(np.arange(0, 23, 2.5))
plt.legend()
plt.grid()
plt.tight_layout()
plt.savefig('stress_pod_deployment.pdf')

