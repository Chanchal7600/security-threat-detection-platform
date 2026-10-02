import requests

url = "http://127.0.0.1:5000/log"

data = {
    "source_ip": "10.204.41.200",
    "event_type": "LOGIN_ATTEMPT",
    "username": "test_user",
    "status": "FAILED",
    "details": "Possible SQL injection: OR 1=1 pattern detected"
}

response = requests.post(url, json=data)

print("Status Code:", response.status_code)
print("Response:", response.json())