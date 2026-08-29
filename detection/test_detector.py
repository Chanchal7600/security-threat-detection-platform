def detect_threat(log):
    """
    Detects suspicious activity from a single security log.
    """

    threats = []

    if (
        log.get("event_type") == "Login Attempt"
        and log.get("status") == "Failed"
    ):
        threats.append("Failed login attempt detected")

    if log.get("status") == "Blocked":
        threats.append("Blocked activity detected")

    return threats


def detect_brute_force(logs, threshold=5):
    """
    Detects possible brute-force attacks.

    A brute-force attack is suspected when the
    same IP address has multiple failed login attempts.
    """

    failed_attempts = {}

    for log in logs:
        if (
            log.get("event_type") == "Login Attempt"
            and log.get("status") == "Failed"
        ):
            ip = log.get("source_ip")

            if ip:
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    threats = []

    for ip, count in failed_attempts.items():
        if count >= threshold:
            threats.append({
                "source_ip": ip,
                "threat_type": "Brute Force Attack",
                "severity": "HIGH",
                "confidence": 95.0,
                "description": f"{count} failed login attempts detected from {ip}"
            })

    return threats