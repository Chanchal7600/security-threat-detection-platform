// ==========================================
// CYBERSECURITY THREAT DETECTION PLATFORM
// Complete Dashboard JavaScript
// ==========================================

// ------------------------------------------
// Load all dashboard data
// ------------------------------------------
async function loadData() {
  try {
    // Get logs from Flask
    const logsResponse = await fetch("/logs");

    if (!logsResponse.ok) {
      throw new Error("Unable to load logs");
    }

    const logs = await logsResponse.json();

    // Get detected threats from Flask
    const threatsResponse = await fetch("/threats");

    if (!threatsResponse.ok) {
      throw new Error("Unable to load threats");
    }

    const threats = await threatsResponse.json();

    // ------------------------------------------
    // TOTAL LOGS
    // ------------------------------------------
    const totalLogs = logs.length;

    // ------------------------------------------
    // DETECTED THREATS
    // Each threat object represents one attack
    // ------------------------------------------
    const detectedThreats = threats.length;

    // ------------------------------------------
    // HIGH SEVERITY
    // ------------------------------------------
    const highSeverity = threats.filter(
      (threat) => threat.severity === "HIGH",
    ).length;

    // ------------------------------------------
    // UPDATE DASHBOARD CARDS
    // ------------------------------------------

    const totalLogsElement = document.getElementById("totalLogs");

    const detectedThreatsElement = document.getElementById("detectedThreats");

    const highSeverityElement = document.getElementById("highSeverity");

    const threatRateElement = document.getElementById("threatRate");

    if (totalLogsElement) {
      totalLogsElement.textContent = totalLogs;
    }

    if (detectedThreatsElement) {
      detectedThreatsElement.textContent = detectedThreats;
    }

    if (highSeverityElement) {
      highSeverityElement.textContent = highSeverity;
    }

    // ------------------------------------------
    // THREAT RATE
    // ------------------------------------------
    let threatRate = 0;

    if (totalLogs > 0) {
      threatRate = (detectedThreats / totalLogs) * 100;
    }

    if (threatRateElement) {
      threatRateElement.textContent = threatRate.toFixed(1) + "%";
    }

    // ------------------------------------------
    // CALCULATE NORMAL LOGS
    //
    // Normal logs = total logs - detected attacks
    //
    // Example:
    // Total logs = 11
    // Detected attacks = 2
    // Normal logs = 9
    // ------------------------------------------
    const normalLogs = Math.max(0, totalLogs - detectedThreats);

    // ------------------------------------------
    // THREAT STATISTICS
    // ------------------------------------------

    const normalLogsElement = document.getElementById("normalLogs");

    const detectedThreatsStatsElement = document.getElementById(
      "detectedThreatsStats",
    );

    const normalBar = document.getElementById("normalBar");

    const threatBar = document.getElementById("threatBar");

    if (normalLogsElement) {
      normalLogsElement.textContent = normalLogs;
    }

    if (detectedThreatsStatsElement) {
      detectedThreatsStatsElement.textContent = detectedThreats;
    }

    // ------------------------------------------
    // STATISTICS BAR WIDTH
    // ------------------------------------------

    if (totalLogs > 0) {
      const normalPercentage = (normalLogs / totalLogs) * 100;

      const threatPercentage = (detectedThreats / totalLogs) * 100;

      if (normalBar) {
        normalBar.style.width = normalPercentage + "%";
      }

      if (threatBar) {
        threatBar.style.width = threatPercentage + "%";
      }
    } else {
      if (normalBar) {
        normalBar.style.width = "0%";
      }

      if (threatBar) {
        threatBar.style.width = "0%";
      }
    }

    // ------------------------------------------
    // DISPLAY DETECTED THREATS
    // ------------------------------------------
    displayThreats(threats);

    // ------------------------------------------
    // DISPLAY SECURITY LOG HISTORY
    // ------------------------------------------
    displayLogs(logs);

    console.log("Dashboard updated successfully");
  } catch (error) {
    console.error("Dashboard Error:", error);
  }
}

// ==========================================
// DISPLAY DETECTED THREATS
// ==========================================

function displayThreats(threats) {
  const threatContainer = document.getElementById("threatList");

  if (!threatContainer) {
    return;
  }

  // Clear old threats
  threatContainer.innerHTML = "";

  // No threats
  if (threats.length === 0) {
    threatContainer.innerHTML = `
            <div class="threat-card">
                <h3>No Threats Detected</h3>
                <p>Your system is currently secure.</p>
            </div>
        `;

    return;
  }

  // Show every detected attack
  threats.forEach((threat) => {
    const threatCard = document.createElement("div");

    threatCard.className = "threat-card";

    threatCard.innerHTML = `

            <h3>
                ${threat.threat_type || "Security Threat"}
            </h3>

            <p>
                <strong>Source IP:</strong>
                ${threat.source_ip || "Unknown"}
            </p>

            <p>
                <strong>Severity:</strong>
                <span class="high">
                    ${threat.severity || "UNKNOWN"}
                </span>
            </p>

            <p>
                <strong>Confidence:</strong>
                ${threat.confidence || 0}%
            </p>

            <p>
                <strong>Description:</strong>
                ${threat.description || "Suspicious activity detected"}
            </p>

            <p>
                <strong>Failed Attempts:</strong>
                ${threat.failed_attempts || 0}
            </p>

        `;

    threatContainer.appendChild(threatCard);
  });
}

// ==========================================
// DISPLAY SECURITY LOG HISTORY
// ==========================================

function displayLogs(logs) {
  const tableBody = document.getElementById("logTableBody");

  if (!tableBody) {
    return;
  }

  // Clear old rows
  tableBody.innerHTML = "";

  // Show newest logs first
  logs.forEach((log) => {
    const row = document.createElement("tr");

    // ------------------------------------------
    // NORMALIZE EVENT TYPE
    // Handles:
    // Login Attempt
    // login_attempt
    // ------------------------------------------

    let eventType = log.event_type || "Unknown";

    // ------------------------------------------
    // NORMALIZE STATUS
    // ------------------------------------------

    let status = log.status || "Unknown";

    // ------------------------------------------
    // DETERMINE DISPLAY STATUS
    // ------------------------------------------

    let displayStatus = "NORMAL";

    // Failed login is suspicious
    if (
      status.toLowerCase() === "failed" ||
      status.toLowerCase() === "threat"
    ) {
      displayStatus = "THREAT";
    }

    // Blocked activity is also threat
    if (status.toLowerCase() === "blocked") {
      displayStatus = "THREAT";
    }

    // ------------------------------------------
    // CREATE TABLE ROW
    // ------------------------------------------

    row.innerHTML = `

            <td>
                ${log.timestamp || "N/A"}
            </td>

            <td>
                ${log.source_ip || "Unknown"}
            </td>

            <td>
                ${eventType}
            </td>

            <td class="${
              displayStatus === "THREAT" ? "threat-status" : "normal-status"
            }">

                ${displayStatus}

            </td>

        `;

    tableBody.appendChild(row);
  });
}

// ==========================================
// REFRESH DATA BUTTON
// ==========================================

async function refreshData() {
  console.log("Refreshing dashboard...");

  await loadData();
}

// ==========================================
// REFRESH LOGS BUTTON
// ==========================================

async function refreshLogs() {
  console.log("Refreshing logs...");

  await loadData();
}

// ==========================================
// SIMULATE FAILED LOGIN
// ==========================================

async function simulateFailedLogin() {
  try {
    console.log("Simulating failed login...");

    const response = await fetch("/simulate-failed-login", {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      throw new Error("Failed to simulate login");
    }

    const result = await response.json();

    console.log("Simulation result:", result);

    // Wait a moment for database update
    await new Promise((resolve) => setTimeout(resolve, 300));

    // Reload everything
    await loadData();
  } catch (error) {
    console.error("Simulation Error:", error);

    alert(
      "Unable to simulate failed login. " +
        "Please make sure Flask server is running.",
    );
  }
}

// ==========================================
// BUTTON EVENT LISTENERS
// ==========================================

document.addEventListener("DOMContentLoaded", function () {
  // ------------------------------------------
  // Refresh Data button
  // ------------------------------------------

  const refreshDataButton = document.getElementById("refreshData");

  if (refreshDataButton) {
    refreshDataButton.addEventListener("click", refreshData);
  }

  // ------------------------------------------
  // Refresh Logs button
  // ------------------------------------------

  const refreshLogsButton = document.getElementById("refreshLogs");

  if (refreshLogsButton) {
    refreshLogsButton.addEventListener("click", refreshLogs);
  }

  // ------------------------------------------
  // Simulate Failed Login button
  // ------------------------------------------

  const simulateButton = document.getElementById("simulateFailedLogin");

  if (simulateButton) {
    simulateButton.addEventListener("click", simulateFailedLogin);
  }

  // ------------------------------------------
  // Load dashboard when page opens
  // ------------------------------------------

  loadData();

  // ------------------------------------------
  // Automatically refresh every 10 seconds
  // ------------------------------------------

  setInterval(loadData, 10000);
});
