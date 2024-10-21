import json
import requests

# Base URL of the server
BASE_URL = "http://localhost:30002"

# Headers for requests
headers = {'Content-Type': 'application/json'}

# Test data for storing a worker whitelist
store_worker_data = {
    "osName": "Debian GNU/Linux 12 (bookworm)",
    "validDigests": {
        "SHA1": [],
        "SHA256": ["7b6436b0c98f62380866d9432c2af0ee08ce16a171bda6951aecd95ee1307d61"]
    }
}

# Test data for checking a worker whitelist
check_worker_data = {
    "osName": "Debian GNU/Linux 12 (bookworm)",
    "bootAggregate": "7b6436b0c98f62380866d9432c2af0ee08ce16a171bda6951aecd95ee1307d61",
    "hashAlg": "SHA256"
}

# Test data for appending new OS to the worker whitelist
worker_data_to_append = {
    "osName": "Debian GNU/Linux 12 (bookworm)",
    "validDigests": {
        "SHA1": [],
        "SHA256": ["6341e6b2646a79a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af2"]
    }
}

# Test data for storing a pod whitelist
store_pod_data = {
    "imageName": "redis:latest",
    "imageDigest": "sha256:abcd1234",
    "validFiles": [
        {
            "filePath": "/bin/busybox",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "59c8d3cd7110e90abe309b4390afc803a9d40dccd48bdd01afbf2abbe6be4e34",
                    "5eab7b965422f7d475bc10d2b2d74d2e399da904e94c08565eef333df800085f"
                ]
            }
        },
        {
            "filePath": "/lib/ld-musl-x86_64.so.1",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "6a1c33fa00fd34a8c6e3ee69767a6e35c96072cb239db6e30246af0695cfd6e0",
                    "966253f07a0f352defe81bb9f77f5b2f0bc1bf5864b6f110a47cfcd521688021"
                ]
            }
        },
        {
            "filePath": "/opt/bin/flanneld",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "7a7a8305290a02361c52e0aa168df8d4741bd7f882af421763675ae8f57894a2"
                ]
            }
        },
        {
            "filePath": "/pause",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "11f8ea63fa5b85b1b0f77c8a794f6b2f196ece6aaa1b2d2a43bd72f9a4de98ff"
                ]
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
def append_worker_whitelist():
    response = requests.post(f"{BASE_URL}/whitelist/worker/os/add", headers=headers, data=json.dumps(store_worker_data))
    print("Add Worker Whitelist Response:", response.status_code, response.json())

# Test function for checking a worker whitelist
def check_worker_whitelist():
    response = requests.post(f"{BASE_URL}/whitelist/worker/os/check", headers=headers, data=json.dumps(check_worker_data))
    print("Check Worker Whitelist Response:", response.status_code, response.json())

# Test function for adding a pod whitelist
def append_pod_whitelist():
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
    append_worker_whitelist()      # Test adding worker whitelist
    check_worker_whitelist()    # Test checking worker whitelist
    #delete_os_from_worker_whitelist("Ubuntu 22.04.6 LTS")
    #append_worker_whitelist()   # Test appending new OS to worker whitelist
    append_pod_whitelist()         # Test adding pod whitelist
    #check_pod_whitelist()       # Test checking pod whitelist
    #delete_file_from_pod_whitelist("nginx:1.21", "/bin/sh")  # Test deleting a file from pod whitelist