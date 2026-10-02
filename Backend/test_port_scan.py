import requests

url = "http://127.0.0.1:5000/log"

ports = [21, 22, 23, 80, 443]

for port in ports:
    data = {
        "source_ip": "10.204.41.201",
        "event_type": "PORT_SCAN",
        "username": "scanner",
        "status": "FAILED",
        "details": f"Connection attempt detected on port {port}"
    }

    response = requests.post(url, json=data)

    print(
        f"Port {port} -> "
        f"Status: {response.status_code}"
    )

print("\nPort scan simulation completed.")