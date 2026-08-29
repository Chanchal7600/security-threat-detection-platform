from log_manager import add_security_log
from datetime import datetime

add_security_log(
    timestamp=datetime.now(),
    source_ip="192.168.1.50",
    event_type="Login Attempt",
    username="admin",
    status="Failed",
    details="Invalid password"
)