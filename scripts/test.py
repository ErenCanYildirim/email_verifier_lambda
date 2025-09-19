import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv('email-verifier-key')
url = os.getenv('email-verifier-lambda-url')

payload = {"email": "test@protonmail.com"}
headers = {"Content-Type": "application/json",
    "x-api-key": api_key
}

response = requests.post(url, headers=headers, json=payload)

data = response.json()

print("Status code:", response.status_code)
#print("Response JSON:", json.dumps(data, indent=2))

body_str = data["body"]
body_dict = json.loads(body_str)

print("safe_to_register:", body_dict["safe_to_register"])
