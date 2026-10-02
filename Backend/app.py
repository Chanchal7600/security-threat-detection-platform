import sys
import os

from flask import Flask, jsonify, send_from_directory, request , session, redirect, url_for
from database import get_db_connection
from user_manager import get_user, verify_password
from functools import wraps

# =========================================================
# ALLOW PYTHON TO FIND DETECTION MODULE
# =========================================================

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from detection.threat_detector import (
    detect_brute_force,
    detect_suspicious_ips,
    detect_blocked_activity,
    detect_sql_injection,
    detect_port_scan
    

)


app = Flask(__name__)
app.secret_key = "security-threat-detection-platform-secret-key"
app.secret_key = "your-secret-key"
def is_ip_blocked(source_ip):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT id FROM blocked_ips WHERE source_ip = %s",
        (source_ip,)
    )

    result = cursor.fetchone()

    cursor.close()
    connection.close()

    return result is not None

def role_required(*allowed_roles):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):

            # User login nahi hai
            if "username" not in session:
                return jsonify({
                    "error": "Authentication required"
                }), 401

            # User ke paas required role nahi hai
            if session.get("role") not in allowed_roles:
                return jsonify({
                    "error": "Access denied"
                }), 403

            return function(*args, **kwargs)

        return wrapper
    return decorator
# =========================================================
# USER LOGIN
# =========================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET" :
        return send_from_directory(
            os.path.join(
            os.path.dirname(
                os.path.dirname(__file__)
            ),
            "frontend"
        ),
        "login.html"
    )
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "error": "No JSON data received"
            }), 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({
                "error": "Username and password are required"
            }), 400

        # Get user's IP address
        source_ip = request.remote_addr

        # Check whether this IP is blocked
        if is_ip_blocked(source_ip):
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute("""
                  INSERT INTO security_logs
                  (
                     timestamp, source_ip, event_type, username, status,
                     details, alert_status, resolution_status
              )
              VALUES
             (NOW(), %s, %s, %s, %s, %s, 'ACTIVE', 'OPEN')
            """, (
            source_ip,
           "BLOCKED_ACTIVITY",
            username,
            "BLOCKED",
            "Login attempt rejected because IP is blocked"
            ))

            connection.commit()
            cursor.close()
            connection.close()

            return jsonify({
              "error": "Access denied. Your IP address has been blocked."
              }), 403
        user = get_user(username)
        # -------------------------------------------------
        # SUCCESSFUL LOGIN
        # -------------------------------------------------
        if user and verify_password(
            password,
            user["password_hash"]
        ):
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO security_logs
                (
                    timestamp,
                    source_ip,
                    event_type,
                    username,
                    status,
                    details,
                    alert_status,
                    resolution_status
                )
                VALUES
                (
                    NOW(),
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    'ACTIVE',
                    'OPEN'
                )
                """,
                (
                    source_ip,
                    "LOGIN",
                    username,
                    "SUCCESS",
                    "Successful login"
                )
            )

            connection.commit()

            cursor.close()
            connection.close()

            session["username"] = username
            session["role"] = user["role"]

            return jsonify({
                "message": "Login successful",
                "username": username,
                
            }), 200

        # -------------------------------------------------
        # FAILED LOGIN
        # -------------------------------------------------
        else:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO security_logs
                (
                    timestamp,
                    source_ip,
                    event_type,
                    username,
                    status,
                    details,
                    alert_status,
                    resolution_status
                )
                VALUES
                (
                    NOW(),
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    'ACTIVE',
                    'OPEN'
                )
                """,
                (
                    source_ip,
                    "LOGIN_FAILED",
                    username,
                    "FAILED",
                    "Invalid username or password"
                )
            )

            connection.commit()

            cursor.close()
            connection.close()

            return jsonify({
                "error": "Invalid username or password"
            }), 401

    except Exception as error:
        print("Login error:", error)

        return jsonify({
            "error": str(error)
        }), 500
    
# =========================================================
# USER LOGOUT
# =========================================================

    
# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    if "username" not in session:
        return jsonify({
            "error": "Please login first"
        }), 401


    return send_from_directory(
        os.path.join(
            os.path.dirname(
                os.path.dirname(__file__)
            ),
            "frontend"
        ),
        "index.html"
    )


# =========================================================
# ADD SECURITY LOG
# =========================================================

@app.route("/log", methods=["POST"])
def add_log():

    try:

        data = request.get_json()

        if not data:
            return jsonify({
                "error": "No JSON data received"
            }), 400


        source_ip = data.get("source_ip")
        event_type = data.get("event_type")
        username = data.get("username")
        status = data.get("status")
        details = data.get("details")


        # Check required value

        if not source_ip:

            return jsonify({
                "error": "Source IP is required"
            }), 400


        connection = get_db_connection()

        cursor = connection.cursor()


        # =================================================
        # INSERT SECURITY LOG
        # =================================================

        cursor.execute(
            """
            INSERT INTO security_logs
            (
                timestamp,
                source_ip,
                event_type,
                username,
                status,
                details,
                alert_status,
                resolution_status
            )
            VALUES
            (
                NOW(),
                %s,
                %s,
                %s,
                %s,
                %s,
                'ACTIVE',
                'OPEN'
            )
            """,
            (
                source_ip,
                event_type,
                username,
                status,
                details
            )
        )


        connection.commit()


        cursor.close()
        connection.close()


        return jsonify({

            "message":
                "Log added successfully",

            "source_ip":
                source_ip,

            "event_type":
                event_type,

            "status":
                status

        })


    except Exception as error:

        print(
            "Error adding log:",
            error
        )

        return jsonify({

            "error":
                str(error)

        }), 500


# =========================================================
# GET ALL SECURITY LOGS
# =========================================================

@app.route("/logs")
def get_logs():

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT *
            FROM security_logs
            ORDER BY timestamp DESC
            """
        )


        logs = cursor.fetchall()


        cursor.close()
        connection.close()


        return jsonify(logs)


    except Exception as error:

        print(
            "Error loading logs:",
            error
        )

        return jsonify({

            "error":
                str(error)

        }), 500


# =========================================================
# DETECT THREATS
# =========================================================

@app.route("/threats")
def get_threats():

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT *
            FROM security_logs
            ORDER BY timestamp DESC
            """
        )


        logs = cursor.fetchall()


        cursor.close()
        connection.close()


        # =================================================
        # RUN DETECTION ALGORITHMS
        # =================================================

        brute_force_threats = detect_brute_force(logs)
        suspicious_ip_threats = detect_suspicious_ips(logs)
        blocked_activity_threats = detect_blocked_activity(logs)
        sql_injection_threats = detect_sql_injection(logs)
        port_scan_threats = detect_port_scan(logs)


     

        # =================================================
        # COMBINE THREATS
        # =================================================

        detected_threats = (
            brute_force_threats
            + suspicious_ip_threats
            + blocked_activity_threats
            + sql_injection_threats
            + port_scan_threats
        )

# Remove duplicate threats
        unique_threats = []
        seen = set()

        for threat in detected_threats:
            key = (
                threat.get("source_ip"),
                threat.get("threat_type")
    )

            if key not in seen:
               seen.add(key)
               unique_threats.append(threat)
        return jsonify(unique_threats)


    except Exception as error:

        print(
            "Error detecting threats:",
            error
        )

        return jsonify({

            "error":
                str(error)

        }), 500

# =========================================================
# THREAT ANALYTICS
# =========================================================
@app.route("/analytics")
def get_analytics():
    try:
        connection = get_db_connection()

        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
            FROM security_logs
            ORDER BY timestamp DESC
        """)

        logs = cursor.fetchall()

        cursor.close()
        connection.close()

        # Run detection algorithms
        brute_force_threats = detect_brute_force(logs)
        suspicious_ip_threats = detect_suspicious_ips(logs)
        blocked_activity_threats = detect_blocked_activity(logs)

        # Total detections
        total_threats = (
            len(brute_force_threats)
            + len(suspicious_ip_threats)
            + len(blocked_activity_threats)
        )

        # -------------------------------------------------
        # FIND TOP ATTACKING IP
        # -------------------------------------------------

        ip_counts = {}

        for threat in (
            brute_force_threats
            + suspicious_ip_threats
            + blocked_activity_threats
        ):
            ip = threat.get("source_ip")

            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

        if ip_counts:
            top_attacking_ip = max(
                ip_counts,
                key=ip_counts.get
            )

            top_attacking_ip_count = ip_counts[
                top_attacking_ip
            ]
        else:
            top_attacking_ip = "N/A"
            top_attacking_ip_count = 0

        # -------------------------------------------------
        # SEVERITY COUNTS
        # -------------------------------------------------

        all_threats = (
            brute_force_threats
            + suspicious_ip_threats
            + blocked_activity_threats
        )

        high_count = sum(
            1
            for threat in all_threats
            if threat.get("severity") == "HIGH"
        )

        medium_count = sum(
            1
            for threat in all_threats
            if threat.get("severity") == "MEDIUM"
        )

        low_count = sum(
            1
            for threat in all_threats
            if threat.get("severity") == "LOW"
        )

        # -------------------------------------------------
        # LOG COUNTS
        # -------------------------------------------------

        threat_logs = 0

        for log in logs:

            status = str(
                log.get("status") or ""
            ).lower()

            event_type = str(
                log.get("event_type") or ""
            ).lower()

            if (
                status in [
                    "failed",
                    "blocked",
                    "threat",
                    "suspicious"
                ]
                or "fail" in event_type
                or "attack" in event_type
                or "brute" in event_type
                or "blocked" in event_type
                or "suspicious" in event_type
            ):
                threat_logs += 1

        normal_logs = max(
            len(logs) - threat_logs,
            0
        )

        # -------------------------------------------------
        # THREAT RATE
        # -------------------------------------------------

        threat_rate = (
            (total_threats / len(logs)) * 100
            if logs
            else 0
        )

        return jsonify({
            "total_logs": len(logs),

            "total_threats": total_threats,

            "brute_force_attacks":
                len(brute_force_threats),

            "suspicious_ip_activity":
                len(suspicious_ip_threats),

            "blocked_activity":
                len(blocked_activity_threats),

            "high_severity":
                high_count,

            "medium_severity":
                medium_count,

            "low_severity":
                low_count,

            "normal_logs":
                normal_logs,

            "threat_logs":
                threat_logs,

            "threat_rate":
                round(threat_rate, 1),

            "top_attacking_ip":
                top_attacking_ip,

            "top_attacking_ip_count":
                top_attacking_ip_count
        })

    except Exception as error:

        print(
            "Analytics error:",
            error
        )

        return jsonify({
            "error": str(error)
        }), 500
    # =========================================================
# THREAT TREND
# =========================================================

@app.route("/trend")
def get_threat_trend():

    try:

        connection = get_db_connection()

        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                timestamp,
                status,
                event_type
            FROM security_logs
            ORDER BY timestamp ASC
        """)

        logs = cursor.fetchall()

        cursor.close()
        connection.close()


        # -------------------------------------------------
        # Group logs by date/hour
        # -------------------------------------------------

        trend = {}


        for log in logs:

            timestamp = log.get("timestamp")

            if not timestamp:
                continue


            # Convert timestamp to string safely
            timestamp_str = str(timestamp)

            # Use date + hour as the trend label
            label = timestamp_str[:13]


            if label not in trend:

                trend[label] = {
                    "normal": 0,
                    "threat": 0
                }


            status = str(
                log.get("status") or ""
            ).lower()


            event_type = str(
                log.get("event_type") or ""
            ).lower()


            # Determine whether this is a threat
            is_threat = (

                status in [
                    "failed",
                    "blocked",
                    "threat",
                    "suspicious"
                ]

                or "fail" in event_type

                or "attack" in event_type

                or "brute" in event_type

                or "blocked" in event_type

                or "suspicious" in event_type

            )


            if is_threat:

                trend[label]["threat"] += 1

            else:

                trend[label]["normal"] += 1


        # -------------------------------------------------
        # Convert dictionary to list
        # -------------------------------------------------

        trend_data = []

        for label, values in trend.items():

            trend_data.append({

                "time": label,

                "normal": values["normal"],

                "threat": values["threat"]

            })


        return jsonify(trend_data)


    except Exception as error:

        print(
            "Threat trend error:",
            error
        )

        return jsonify({
            "error": str(error)
        }), 500
    
# =========================================================
# ACTIVE SECURITY ALERTS
# =========================================================

@app.route("/alerts")
def get_alerts():

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT *
            FROM security_logs
            ORDER BY timestamp DESC
            """
        )


        logs = cursor.fetchall()


        cursor.close()
        connection.close()


        # =================================================
        # RUN DETECTION ALGORITHMS
        # =================================================

        brute_force_threats = detect_brute_force(logs)

        suspicious_ip_threats = detect_suspicious_ips(logs)

        blocked_activity_threats = detect_blocked_activity(logs)
        sql_injection_threats =detect_sql_injection(logs)
        port_scan_threats = detect_port_scan(logs)


        detected_threats = (
            brute_force_threats
            +
            suspicious_ip_threats
            +
            blocked_activity_threats
            +
            sql_injection_threats
            +
            port_scan_threats
        )


        alerts = []


        # =================================================
        # MATCH THREATS WITH DATABASE STATUS
        # =================================================

        for threat in detected_threats:

            source_ip = \
                threat.get("source_ip")

            alert_status = "ACTIVE"

            resolution_status = "OPEN"


            for log in logs:

                if (
                    log.get("source_ip")
                    == source_ip
                ):

                    database_alert_status = \
                        log.get("alert_status")

                    database_resolution_status = \
                        log.get("resolution_status")


                    if database_alert_status:

                        alert_status = \
                            database_alert_status


                    if database_resolution_status:

                        resolution_status = \
                            database_resolution_status


                    break


            # Add status information

            threat["alert_status"] = \
                alert_status

            threat["resolution_status"] = \
                resolution_status


            alerts.append(threat)


        return jsonify(alerts)


    except Exception as error:

        print(
            "Error loading alerts:",
            error
        )

        return jsonify({

            "error":
                str(error)

        }), 500

@app.route("/system-status")
def system_status():

    database_status = "DISCONNECTED"

    try:
        connection = get_db_connection()

        if connection:
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()

            cursor.close()
            connection.close()

            database_status = "CONNECTED"

    except Exception as e:
        print("Database health check failed:", e)

    return jsonify({
        "detection_engine": "ACTIVE",
        "log_monitoring": "ACTIVE",
        "alert_monitoring": "ACTIVE",
        "database": database_status
    })
# =========================================================
# ACKNOWLEDGE ALERT
# =========================================================

@app.route(
    "/alerts/acknowledge",
    methods=["POST"]
)
@role_required("ADMIN", "SECURITY_ANALYST")
def acknowledge_alert():

    try:

        data = request.get_json()


        if not data:

            return jsonify({

                "error":
                    "No JSON data received"

            }), 400


        source_ip = \
            data.get("source_ip")

        threat_type = \
            data.get("threat_type")


        if not source_ip:

            return jsonify({

                "error":
                    "Source IP is required"

            }), 400


        connection = \
            get_db_connection()

        cursor = \
            connection.cursor()


        # =================================================
        # ACKNOWLEDGE ALL ALERTS FROM THIS IP
        # =================================================

        cursor.execute(
            """
            UPDATE security_logs

            SET alert_status = 'ACKNOWLEDGED'

            WHERE source_ip = %s
            """,
            (
                source_ip,
            )
        )


        connection.commit()


        updated_rows = \
            cursor.rowcount


        cursor.close()
        connection.close()


        return jsonify({

            "message":
                "Alert acknowledged successfully",

            "source_ip":
                source_ip,

            "threat_type":
                threat_type,

            "status":
                "ACKNOWLEDGED",

            "updated_rows":
                updated_rows

        })


    except Exception as error:

        print(
            "Error acknowledging alert:",
            error
        )

        return jsonify({

            "error":
                str(error)

        }), 500


# =========================================================
# RESOLVE ALERT
# =========================================================
@app.route("/alerts/resolve", methods=["POST"])
@role_required("ADMIN", "SECURITY_ANALYST")
def resolve_alert():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No JSON data received"}), 400

        source_ip = data.get("source_ip")
        threat_type = data.get("threat_type")

        if not source_ip:
            return jsonify({"error": "Source IP is required"}), 400

        connection = get_db_connection()
        cursor = connection.cursor()

        # 1. Add IP to blocked IP list
        cursor.execute("""
            INSERT IGNORE INTO blocked_ips
            (source_ip, reason)
            VALUES (%s, %s)
        """, (
            source_ip,
            threat_type or "Security Threat"
        ))

        # 2. Mark alert as resolved
        cursor.execute("""
            UPDATE security_logs
            SET resolution_status = 'RESOLVED'
            WHERE source_ip = %s
        """, (source_ip,))

        connection.commit()

        updated_rows = cursor.rowcount

        cursor.close()
        connection.close()

        return jsonify({
            "message": "Alert resolved and IP blocked successfully",
            "source_ip": source_ip,
            "threat_type": threat_type,
            "status": "RESOLVED",
            "ip_blocked": True,
            "updated_rows": updated_rows
        }), 200 

    except Exception as error:
        print("Error resolving alert:", error)
        return jsonify({"error": str(error)}), 500

    

@app.route("/alerts/unblock", methods=["POST"])
@role_required("ADMIN")
def unblock_ip():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No JSON data received"}), 400

        source_ip = data.get("source_ip")

        if not source_ip:
            return jsonify({"error": "Source IP is required"}), 400

        connection = get_db_connection()
        cursor = connection.cursor()

        # Remove IP from blocked list
        cursor.execute("""
            DELETE FROM blocked_ips
            WHERE source_ip = %s
        """, (source_ip,))

        connection.commit()

        deleted_rows = cursor.rowcount

        cursor.close()
        connection.close()

        if deleted_rows == 0:
            return jsonify({
                "error": "IP address was not found in blocked list"
            }), 404

        return jsonify({
            "message": "IP unblocked successfully",
            "source_ip": source_ip,
            "status": "UNBLOCKED"
        }), 200

    except Exception as error:
        print("Error unblocking IP:", error)
        return jsonify({"error": str(error)}), 500        


@app.route("/current-user")
def current_user():
    if "username" not in session:
        return jsonify({
            "authenticated": False
        }), 401

    return jsonify({
        "authenticated": True,
        "username": session["username"],
        "role": session.get("role")
    }), 200
# =========================================================
# START FLASK SERVER
# =========================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/login")