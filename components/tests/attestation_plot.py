import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta
from matplotlib import rcParams

rcParams['font.weight'] = 'bold'

pods_num_list = [20, 40, 60, 80, 100]  # Example number of pods
attestation_times = [22, 74, 122, 173, 260]
attestation_cpu = [18.17, 19.76, 23.68, 24.47, 38.78]

# CPU Usage Plot
plt.figure(figsize=(9, 5))
plt.plot(pods_num_list, attestation_times, label='Pod Attestation', color='r', marker='o')
plt.xlabel('Number of Pods', weight='bold')
plt.ylabel('Time (s)', weight='bold')
plt.legend()
#plt.xticks(np.arange(0, 13, 1))
plt.yticks(np.arange(20, 270, 20))
plt.tight_layout()
plt.grid()
plt.savefig('pod_attestation_time.pdf')

# Time Plot
plt.figure(figsize=(9, 5))
plt.plot(pods_num_list, attestation_cpu, label='Pod Attestation', color='r', marker='o')
plt.xlabel('Number of Pods', weight='bold')
plt.ylabel('CPU Usage (%)', weight='bold')
plt.legend()
#plt.xticks(np.arange(0, 13, 1))
plt.yticks(np.arange(15, 41, 3))
plt.tight_layout()
plt.grid()
plt.savefig('pod_attestation_cpu.pdf')

