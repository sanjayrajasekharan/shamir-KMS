import argparse
import json
import requests

# Define the headers and other parameters for the request
headers = {"Content-Type": "application/json"}
cert = ("operator1-cert.pem", "operator1-key.pem")
verify = "cert.pem"

# Set up command line arguments
parser = argparse.ArgumentParser(description='Send an encrypt request to shamir KMS')
parser.add_argument('--domain', help='The domain to send the request to.')
parser.add_argument('--key_id', help='The ID of the key to generate.')
parser.add_argument('--plaintext', help='The plaintext to encrypt.')

args = parser.parse_args()

# Define the URL for the request
url = f"https://{args.domain}:8080/v1/keys/encrypt"

# Define the payload for the request
payload = {
    "keyID": args.key_id,
    "plaintext": args.plaintext,  # Replace with your actual ciphertext
}

# Send the request
response = requests.post(url, headers=headers, data=json.dumps(payload), cert=cert, verify=False)

# Print the response
print(response.status_code)
print(response.text)
