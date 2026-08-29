from threat_detector import detect_brute_force

test_logs = [
    {
        "source_ip": "192.168.1.50",
        "event_type": "Login Attempt",
        "status": "Failed"
    },
    {
        "source_ip": "192.168.1.50",
        "event_type": "Login Attempt",
        "status": "Failed"
    },
    {
        "source_ip": "192.168.1.50",
        "event_type": "Login Attempt",
        "status": "Failed"
    },
    {
        "source_ip": "192.168.1.50",
        "event_type": "Login Attempt",
        "status": "Failed"
    },
    {
        "source_ip": "192.168.1.50",
        "event_type": "Login Attempt",
        "status": "Failed"
    }
]

result = detect_brute_force(test_logs)

print("Detected threats:")
print(result)