import json

import requests

# Base URL of the server
BASE_URL = "http://localhost:9090"

# Headers for requests
headers = {'Content-Type': 'application/json'}

# Test data for storing a worker whitelist
store_worker_data = {
    "osName": "Ubuntu 20.04.6 LTS",
    "validDigests": {
        "SHA1": [],
        "SHA256": ["5341e6b2646979a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af1"]
    }
}

# Test data for checking a worker whitelist
check_worker_data = {
    "osName": "Ubuntu 20.04.6 LTS",
    "bootAggregate": "5341e6b2646979a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af1",
    "hashAlg": "SHA256"
}

# Test data for appending new OS to the worker whitelist
worker_data_to_append = {
    "osName": "Ubuntu 22.04.6 LTS",
    "validDigests": {
        "SHA1": [],
        "SHA256": ["6341e6b2646a79a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af2"]
    }
}

# Test data for storing a pod whitelist
store_pod_data = {
    "imageName": "nginx:1.21",
    "imageDigest": "sha256:abcd1234",
    "validFiles": [
        {
            "filePath": "/bin/sh",
            "validDigests": {
                "SHA1": [],
                "SHA256": ["c157a79031e1c40f85931829bc5fc552"]
            }
        },
        {
            "filePath": "/bin/kmod",
            "validDigests": {
                "SHA1": [],
                "SHA256": ["b157a79031e1c40f85931829bc5fc452"]
            }
        }
    ]
}

# Test data for checking a pod whitelist
check_pod_data = {
    "podImageName": "nginx:1.21",
    "podFiles": [
        {
            "filePath": "/bin/sh",
            "fileHash": "c157a79031e1c40f85931829bc5fc552"
        },
        {
            "filePath": "/bin/kmod",
            "fileHash": "b157a79031e1c40f85931829bc5fc452"
        }
    ],
    "hashAlg": "SHA256"
}


# Test function for adding a worker whitelist
def add_worker_whitelist():
    response = requests.post(f"{BASE_URL}/whitelist/worker/add", headers=headers, data=json.dumps(store_worker_data))
    print("Add Worker Whitelist Response:", response.status_code, response.json())

# Test function for checking a worker whitelist
def check_worker_whitelist():
    response = requests.post(f"{BASE_URL}/whitelist/worker/check", headers=headers, data=json.dumps(check_worker_data))
    print("Check Worker Whitelist Response:", response.status_code, response.json())

# Test function for appending to a worker whitelist
def append_worker_whitelist():
    response = requests.post(f"{BASE_URL}/whitelist/worker/add", headers=headers, data=json.dumps(worker_data_to_append))
    print("Append Worker Whitelist Response:", response.status_code, response.json())

# Test function for adding a pod whitelist
def add_pod_whitelist():
    response = requests.post(f"{BASE_URL}/whitelist/pod/image/add", headers=headers, data=json.dumps(store_pod_data))
    print("Add Pod Whitelist Response:", response.status_code, response.json())

# Test function for checking a pod whitelist
def check_pod_whitelist():
    response = requests.post(f"{BASE_URL}/whitelist/pod/check", headers=headers, data=json.dumps(check_pod_data))
    print("Check Pod Whitelist Response:", response.status_code, response.json())

# Test function for deleting a file from pod whitelist
def delete_os_from_worker_whitelist(osName):
    # The image name and file path are passed as query parameters
    response = requests.delete(f"{BASE_URL}/whitelist/worker/delete", headers=headers, params={"osName": osName})
    print("Delete Os from Worker Whitelist Response:", response.status_code, response.text)

# Test function for deleting a file from pod whitelist
def delete_file_from_pod_whitelist(image_name, file_path):
    # The image name and file path are passed as query parameters
    response = requests.delete(f"{BASE_URL}/whitelist/pod/image/file/delete", headers=headers, params={"filePath": "/bin/kmod", "imageName": image_name})
    print("Delete File from Pod Whitelist Response:", response.status_code, response.text)


# Running the tests
if __name__ == "__main__":
    #add_worker_whitelist()      # Test adding worker whitelist
    #check_worker_whitelist()    # Test checking worker whitelist
    delete_os_from_worker_whitelist("Ubuntu 22.04.6 LTS")
    #append_worker_whitelist()   # Test appending new OS to worker whitelist
    #add_pod_whitelist()         # Test adding pod whitelist
    #check_pod_whitelist()       # Test checking pod whitelist
    #delete_file_from_pod_whitelist("nginx:1.21", "/bin/sh")  # Test deleting a file from pod whitelist
