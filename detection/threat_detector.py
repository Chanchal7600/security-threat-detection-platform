# =========================================================
# BRUTE FORCE DETECTION
# =========================================================

def detect_brute_force(logs, threshold=5):
    """
    Detect possible brute-force attacks.
    """

    failed_attempts = {}

    for log in logs:

        event_type = str(
            log.get("event_type", "")
        ).lower()

        status = str(
            log.get("status", "")
        ).lower()

        if (
            event_type in [
                "login_attempt",
                "login attempt",
                "login_failed"
           ]
           and status == "failed"
    ):

            ip = log.get("source_ip")

            if ip:

                failed_attempts[ip] = (
                    failed_attempts.get(ip, 0) + 1
                )

    threats = []

    for ip, count in failed_attempts.items():

        if count >= threshold:

            threats.append({

                "source_ip": ip,

                "threat_type":
                    "Brute Force Attack",

                "severity":
                    "HIGH",

                "confidence":
                    95.0,

                "failed_attempts":
                    count,

                "description":
                    f"{count} failed login attempts detected from {ip}"

            })

    return threats


# =========================================================
# SUSPICIOUS IP DETECTION
# =========================================================

def detect_suspicious_ips(logs, threshold=10):
    """
    Detect IP addresses generating
    an unusually high number of logs.
    """

    ip_activity = {}

    for log in logs:

        ip = log.get("source_ip")

        if ip:

            ip_activity[ip] = (
                ip_activity.get(ip, 0) + 1
            )

    threats = []

    for ip, count in ip_activity.items():

        if count >= threshold:

            threats.append({

                "source_ip":
                    ip,

                "threat_type":
                    "Suspicious IP Activity",

                "severity":
                    "MEDIUM",

                "confidence":
                    85.0,

                "failed_attempts":
                    count,

                "description":
                    f"Unusual activity detected from {ip} with {count} security events"

            })

    return threats


# =========================================================
# BLOCKED ACTIVITY DETECTION
# =========================================================

def detect_blocked_activity(logs):
    """
    Detect blocked security activity.

    Any security log with status 'Blocked'
    is treated as suspicious activity.
    """

    blocked_activity = {}

    for log in logs:

        status = str(
            log.get("status", "")
        ).lower()

        if status == "blocked":

            ip = log.get("source_ip")

            if ip:

                blocked_activity[ip] = (
                    blocked_activity.get(ip, 0) + 1
                )

    threats = []

    for ip, count in blocked_activity.items():

        threats.append({

            "source_ip":
                ip,

            "threat_type":
                "Blocked Suspicious Activity",

            "severity":
                "MEDIUM",

            "confidence":
                90.0,

            "failed_attempts":
                count,

            "description":
                f"{count} blocked security event(s) detected from {ip}"

        })

    return threats


# =========================================================
# SQL INJECTION DETECTION
# =========================================================

def detect_sql_injection(logs):
    """
    Detect common SQL injection patterns
    in security log details.

    This is a defensive log-analysis rule.
    """

    sql_patterns = [
        "union select",
        "select * from",
        "or 1=1",
        "' or '1'='1",
        "drop table",
        "insert into",
        "delete from",
        "update users",
        "sql injection"
    ]

    threats = []

    for log in logs:

        details = str(
            log.get("details", "")
        ).lower()

        event_type = str(
            log.get("event_type", "")
        ).lower()

        combined_text = (
            details + " " + event_type
        )

        detected_pattern = None

        for pattern in sql_patterns:

            if pattern in combined_text:

                detected_pattern = pattern
                break

        if detected_pattern:

            ip = log.get(
                "source_ip",
                "Unknown"
            )

            threats.append({

                "source_ip":
                    ip,

                "threat_type":
                    "SQL Injection Attempt",

                "severity":
                    "HIGH",

                "confidence":
                    92.0,

                "failed_attempts":
                    1,

                "description":
                    f"Possible SQL injection pattern detected from {ip}"

            })

    return threats
# =========================================================
# PORT SCAN DETECTION
# =========================================================

def detect_port_scan(logs, threshold=5):
    """
    Detect possible port scanning activity.

    If the same IP attempts connections to
    multiple different ports, it is treated
    as possible port scanning.
    """

    ip_ports = {}

    for log in logs:
        event_type = str(
            log.get("event_type", "")
        ).lower()

        if event_type not in [
            "port_scan",
            "connection_attempt",
            "port_attempt"
        ]:
            continue

        ip = log.get("source_ip")
        details = str(log.get("details", ""))

        if not ip:
            continue

        # Extract port number from details
        import re

        match = re.search(
            r"\bport\s+(\d{1,5})\b",
            details.lower()
        )

        if match:
            port = int(match.group(1))

            if ip not in ip_ports:
                ip_ports[ip] = set()

            ip_ports[ip].add(port)

    threats = []

    for ip, ports in ip_ports.items():

        if len(ports) >= threshold:
            threats.append({
                "source_ip": ip,
                "threat_type": "Port Scan Attack",
                "severity": "MEDIUM",
                "confidence": 90.0,
                "failed_attempts": len(ports),
                "description": (
                    f"Possible port scanning detected from {ip}. "
                    f"{len(ports)} different ports were targeted."
                )
            })

    return threats