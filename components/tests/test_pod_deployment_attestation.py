import base64
import json
import random
import time
import requests
import rsa

# Define API endpoints
REGISTRAR_BASE_URL = 'http://localhost:30000'  # Ensure this matches your pod-handler URL
POD_HANDLER_BASE_URL = 'http://localhost:30002'
CREATE_TENANT_URL = f'{REGISTRAR_BASE_URL}/tenant/create'
VERIFY_SIGNATURE_URL = f'{REGISTRAR_BASE_URL}/tenant/verify'
POD_DEPLOYMENT_URL = f'{POD_HANDLER_BASE_URL}/pod/deploy'
POD_ATTEST_URL = f'{POD_HANDLER_BASE_URL}/pod/attest'

# Generate RSA keys (for demonstration purposes)
(public_key, private_key) = rsa.newkeys(1024)


# Convert the public key to PEM format
def public_key_to_pem(public_key):
    pem_key = public_key.save_pkcs1(format='PEM')
    return pem_key.decode()


def create_tenant(name, public_key):
    headers = {'Content-Type': 'application/json'}
    data = {
        'name': name,
        'publicKey': public_key_to_pem(public_key)  # Pass public key in PEM format
    }
    response = requests.post(CREATE_TENANT_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 201:
        print('Tenant created successfully')
    else:
        print('Error creating tenant:', response.text)


def sign_message(message):
    # Hash and sign the message
    signature = rsa.sign(message.encode(), private_key, 'SHA-256')
    return base64.b64encode(signature).decode()


def verify_signature(name, message, signature):
    headers = {'Content-Type': 'application/json'}
    data = {
        'tenantName': name,
        'manifest': message,  # Send the entire YAML content as the message
        'signature': signature
    }
    response = requests.post(POD_DEPLOYMENT_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        print('Signature verification successful')
    else:
        print('Signature verification failed:', response.text)


def pod_attestation(name, podName, signature):
    headers = {'Content-Type': 'application/json'}
    data = {
        'tenantName': name,
        'podName': podName,  # Send the entire YAML content as the message
        'signature': signature
    }
    response = requests.post(POD_ATTEST_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 201:
        print('Pod attestation request sent')
    else:
        print('Pod attestation request failed:', response.text)

# Usage
tenant_name = f'Tenant-{random.randint(0, 500)}'
message = '''
apiVersion: v1
kind: Pod
metadata:
  namespace: default
  name: redis-pod
  labels:
    app: redis
spec:
  nodeName: worker  # Specify the node where you want to deploy the pod
  containers:
  - name: redis
    image: redis:latest
    ports:
    - containerPort: 6379
'''

pod_name = "redis-pod"

# Create a new tenant with the public key in PEM format
create_tenant(tenant_name, public_key)

# Sign the YAML content (message)
signature = sign_message(message)

# Verify the signature
verify_signature(tenant_name, message, signature)

signature = sign_message(pod_name)

time.sleep(5)

pod_attestation(tenant_name, pod_name, signature)