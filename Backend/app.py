import sys
import os

from flask import Flask, jsonify, send_from_directory, request

from database import get_db_connection


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
    detect_blocked_activity
)


app = Flask(__name__)


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

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

        if not source_ip:
            return jsonify({
                "error": "Source IP is required"
            }), 400

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
                alert_status
            )
            VALUES
            (
                NOW(),
                %s,
                %s,
                %s,
                %s,
                %s,
                'ACTIVE'
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
            "message": "Log added successfully",
            "source_ip": source_ip,
            "event_type": event_type,
            "status": status
        })

    except Exception as error:

        print("Error adding log:", error)

        return jsonify({
            "error": str(error)
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

        print("Error loading logs:", error)

        return jsonify({
            "error": str(error)
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

        # Run detection algorithms

        brute_force_threats = detect_brute_force(logs)

        suspicious_ip_threats = detect_suspicious_ips(logs)

        blocked_activity_threats = detect_blocked_activity(logs)

        # Combine all threats

        threats = (
            brute_force_threats
            + suspicious_ip_threats
            + blocked_activity_threats
        )

        return jsonify(threats)

    except Exception as error:

        print("Error detecting threats:", error)

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

        # Run detection algorithms

        brute_force_threats = detect_brute_force(logs)

        suspicious_ip_threats = detect_suspicious_ips(logs)

        blocked_activity_threats = detect_blocked_activity(logs)

        detected_threats = (
            brute_force_threats
            + suspicious_ip_threats
            + blocked_activity_threats
        )

        alerts = []

        # Match detected threats with database alert status

        for threat in detected_threats:

            source_ip = threat.get("source_ip")

            alert_status = "ACTIVE"

            for log in logs:

                if log.get("source_ip") == source_ip:

                    database_status = log.get(
                        "alert_status"
                    )

                    if database_status:
                        alert_status = database_status

                    break

            threat["alert_status"] = alert_status

            alerts.append(threat)

        return jsonify(alerts)

    except Exception as error:

        print("Error loading alerts:", error)

        return jsonify({
            "error": str(error)
        }), 500


# =========================================================
# ACKNOWLEDGE ALERT
# =========================================================

@app.route(
    "/alerts/acknowledge",
    methods=["POST"]
)
def acknowledge_alert():

    try:

        data = request.get_json()

        if not data:
            return jsonify({
                "error": "No JSON data received"
            }), 400

        source_ip = data.get("source_ip")

        threat_type = data.get("threat_type")

        if not source_ip:
            return jsonify({
                "error": "Source IP is required"
            }), 400

        connection = get_db_connection()

        cursor = connection.cursor()

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

        updated_rows = cursor.rowcount

        cursor.close()
        connection.close()

        return jsonify({
            "message": "Alert acknowledged successfully",
            "source_ip": source_ip,
            "threat_type": threat_type,
            "status": "ACKNOWLEDGED",
            "updated_rows": updated_rows
        })

    except Exception as error:

        print(
            "Error acknowledging alert:",
            error
        )

        return jsonify({
            "error": str(error)
        }), 500


# =========================================================
# START FLASK SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )