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

store_pod_data = {
    "imageName": "redis:latest",
    "imageDigest": "sha256:a06cea905344470eb49c972f3d030e22f28f632c1b4f43bbe4a26a4329dd6be5",
    "validFiles": [
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "88024463c275711c29f6ac2920a5d3174349d8802720e2df1656637c18d8efba"
                ]
            }
        },
        {
            "filePath": "/usr/bin/id",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "a3d987dd3f9ec0610dc13b7fdccef84895628065434f44247a65ef0d2a341b3c"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libselinux.so.1",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "0207e4908ea384e186c75925b0e56996a3eccecd48c99252aeb757d0d3451c93"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "19c626251526131ac9340826c8f7bcb693c6ceb9d5da55919c3aa45d972b704f"
                ]
            }
        },
        {
            "filePath": "/usr/bin/find",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "c703b94ad3448bccc79cda80520964c8d371918a39eecc27f8d60f4e8891770a"
                ]
            }
        },
        {
            "filePath": "/usr/local/bin/docker-entrypoint.sh",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "c211bc06cdc6bd3fa4752394767359159cbdbdfe1c2c7f445e600419e4c52091"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "6d8337d3d1648ed3f42eccdc90044505bd19b042c496d05c4c4cd3dfdddd9b24"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "4d351715e334aa32eebeb2f03f376e5c961a47f73b37f36885c281ce6e24bb57"
                ]
            }
        },
        {
            "filePath": "/usr/bin/dash",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "f5adb8bf0100ed0f8c7782ca5f92814e9229525a4b4e0d401cf3bea09ac960a6"
                ]
            }
        },
        {
            "filePath": "/usr/local/bin/redis-server",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "6a4bf24ed035ca81c3b339d67953d942261af2156a01753601c5b05c30f0b72c"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libm.so.6",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "958fd4988943ab6713d04d4c7de8e468e358c5671db2acf9a7b025b465d10910"
                ]
            }
        },
        {
            "filePath": "/usr/local/bin/gosu",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "bbc4136d03ab138b1ad66fa4fc051bafc6cc7ffae632b069a53657279a450de3"
                ]
            }
        },
        {
            "filePath": "/pause",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "11ef55f97205c88f7e1f680ce02eb581534d2ef654b823089ac258db56ca04d2"
                ]
            }
        },
        {
            "filePath": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "validDigests": {
                "SHA1": [],
                "SHA256": [
                    "4d13ab2d0a566eaeefbd493fffc3eca25fad9be4136c2796958906fa9c63d0f2"
                ]
            }
        }
    ]
}

'''
[{"filePath":"/usr/lib/x86_64-linux-gnu/libc.so.6","fileHash":"88024463c275711c29f6ac2920a5d3174349d8802720e2df1656637c18d8efba"},{"filePath":"/usr/bin/id","fileHash":"a3d987dd3f9ec0610dc13b7fdccef84895628065434f44247a65ef0d2a341b3c"},{"filePath":"/usr/lib/x86_64-linux-gnu/libselinux.so.1","fileHash":"0207e4908ea384e186c75925b0e56996a3eccecd48c99252aeb757d0d3451c93"},{"filePath":"/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2","fileHash":"19c626251526131ac9340826c8f7bcb693c6ceb9d5da55919c3aa45d972b704f"},{"filePath":"/usr/bin/find","fileHash":"c703b94ad3448bccc79cda80520964c8d371918a39eecc27f8d60f4e8891770a"},{"filePath":"/usr/local/bin/docker-entrypoint.sh","fileHash":"c211bc06cdc6bd3fa4752394767359159cbdbdfe1c2c7f445e600419e4c52091"},{"filePath":"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2","fileHash":"6d8337d3d1648ed3f42eccdc90044505bd19b042c496d05c4c4cd3dfdddd9b24"},{"filePath":"/usr/lib/x86_64-linux-gnu/libssl.so.3","fileHash":"4d351715e334aa32eebeb2f03f376e5c961a47f73b37f36885c281ce6e24bb57"},{"filePath":"/usr/bin/dash","fileHash":"f5adb8bf0100ed0f8c7782ca5f92814e9229525a4b4e0d401cf3bea09ac960a6"},{"filePath":"/usr/local/bin/redis-server","fileHash":"6a4bf24ed035ca81c3b339d67953d942261af2156a01753601c5b05c30f0b72c"},{"filePath":"/usr/lib/x86_64-linux-gnu/libm.so.6","fileHash":"958fd4988943ab6713d04d4c7de8e468e358c5671db2acf9a7b025b465d10910"},{"filePath":"/usr/local/bin/gosu","fileHash":"bbc4136d03ab138b1ad66fa4fc051bafc6cc7ffae632b069a53657279a450de3"},{"filePath":"/pause","fileHash":"11ef55f97205c88f7e1f680ce02eb581534d2ef654b823089ac258db56ca04d2"},{"filePath":"/usr/lib/x86_64-linux-gnu/libcrypto.so.3","fileHash":"4d13ab2d0a566eaeefbd493fffc3eca25fad9be4136c2796958906fa9c63d0f2"}]
'''


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
    #check_worker_whitelist()    # Test checking worker whitelist
    #delete_os_from_worker_whitelist("Ubuntu 22.04.6 LTS")
    #append_worker_whitelist()   # Test appending new OS to worker whitelist
    append_pod_whitelist()         # Test adding pod whitelist
    #check_pod_whitelist()       # Test checking pod whitelist
    #delete_file_from_pod_whitelist("nginx:1.21", "/bin/sh")  # Test deleting a file from pod whitelist