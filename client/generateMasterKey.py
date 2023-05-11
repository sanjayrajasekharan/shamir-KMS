import argparse
import base64
import json
import requests

# Define the headers and other parameters for the request
headers = {"Content-Type": "application/json"}
cert = ("operator1-cert.pem", "operator1-key.pem")
verify = "cert.pem"

# Set up command line arguments
parser = argparse.ArgumentParser(description='Send a POST request with certificates.')
parser.add_argument('domain', help='The domain to send the request to.')
parser.add_argument('cert_paths', nargs='+', help='The paths to the certificate files.')
args = parser.parse_args()

# Define the URL for the request
url = f"https://{args.domain}:8080/v1/keys/generate"

# Read the certificate files and encode their contents
engineerCerts = []
for path in args.cert_paths:
    with open(path, "rb") as f:
        engineerCerts.append(f.read())

# Define the payload for the request
payload = {
    "keyType": "AES_256_GCM",
    "keyID": "test-key2",
    "k": 4,
    "engineerCerts": engineerCerts,
}

# Send the request
response = requests.post(url, headers=headers, data=json.dumps(payload), cert=cert, verify=verify)

# Print the response
print(response.status_code)
print(response.text)
