import requests
import rsa
import json
import base64
import pem

# Define API endpoints
BASE_URL = 'http://localhost:8080'
CREATE_TENANT_URL = f'{BASE_URL}/tenant/create'
VERIFY_SIGNATURE_URL = f'{BASE_URL}/tenant/verify'

# Generate RSA keys (for demonstration purposes)
(public_key, private_key) = rsa.newkeys(512)

# Convert the public key to PEM format
def public_key_to_pem(public_key):
    pem_key = public_key.save_pkcs1(format='PEM')
    return pem_key.decode()

def create_tenant(tenant_id, name, public_key):
    headers = {'Content-Type': 'application/json'}
    data = {
        'tenantId': tenant_id,
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
        'name': name,
        'message': message,
        'signature': signature
    }
    response = requests.post(VERIFY_SIGNATURE_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        print('Signature verification successful')
    else:
        print('Signature verification failed:', response.text)

# Usage
tenant_id = '1'
tenant_name = 'TenantA'
message = 'This is a test message'

# Create a new tenant with the public key in PEM format
create_tenant(tenant_id, tenant_name, public_key)

# Sign the message
signature = sign_message(message)

# Verify the signature
verify_signature(tenant_name, message, signature)
