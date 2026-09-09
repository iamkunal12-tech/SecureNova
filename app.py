import json
import os
import re
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="AegisNet AI API - SIH26155")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConfigPayload(BaseModel):
    config: str

def load_demo_data():
    current_dir = os.path.dirname(__file__)
    json_path = os.path.join(current_dir, "demo_data.json")
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)

DEVICES = load_demo_data()

@app.get("/")
def read_root():
    return {"message": "AegisNet AI API - SIH26155"}

@app.get("/devices")
def get_devices():
    return DEVICES

@app.get("/devices/{device_id}")
def get_device(device_id: int):
    for device in DEVICES:
        if device["id"] == device_id:
            return device
    return {"error": "Device not found"}

@app.get("/summary")
def get_summary():
    total = len(DEVICES)
    compliant = sum(1 for d in DEVICES if d.get("status") == "green")
    avg_compliance = sum(d.get("compliance", 0) for d in DEVICES) / total if total > 0 else 0
    return {
        "total_devices": total,
        "compliant_devices": compliant,
        "average_compliance": round(avg_compliance, 2)
    }

# ================================
# CISCO IOS ANALYZER ENGINE
# ================================
def evaluate_cisco(config_text: str):
    findings = []
    lines = [l.strip().lower() for l in config_text.splitlines() if l.strip()]
    full_text = "\n".join(lines)

    # 1. Telnet Disabled
    has_telnet = any(
        "transport input telnet" in l or
        "transport input all" in l
        for l in lines
    )

    if has_telnet:
        findings.append({
            "control": "Telnet disabled",
            "status": "FAIL",
            "severity": "HIGH",
            "reason": "Telnet is enabled. Plaintext protocol exposes administrative credentials.",
            "remediation": "no transport input telnet"
        })
    else:
        findings.append({
            "control": "Telnet disabled",
            "status": "PASS",
            "severity": "HIGH",
            "reason": "Telnet access is suppressed on management terminal lines.",
            "remediation": "N/A"
        })

    # 2. HTTP Server Disabled
    if re.search(
        r"^ip\s+http\s+server\b",
        full_text,
        re.MULTILINE
    ):
        findings.append({
            "control": "HTTP disabled",
            "status": "FAIL",
            "severity": "HIGH",
            "reason": "Plaintext HTTP management server is active; HTTPS must be enforced.",
            "remediation": "no ip http server"
        })
    else:
        findings.append({
            "control": "HTTP disabled",
            "status": "PASS",
            "severity": "HIGH",
            "reason": "Insecure HTTP web server is not running.",
            "remediation": "N/A"
        })

    # 3. SSH Enabled
    has_ssh = (
        re.search(
            r"^ip\s+ssh\s+version\s+2\b",
            full_text,
            re.MULTILINE
        )
        or "transport input ssh" in full_text
    )

    if has_ssh:
        findings.append({
            "control": "SSH enabled",
            "status": "PASS",
            "severity": "MEDIUM",
            "reason": "Cryptographically secure SSH remote administration is active.",
            "remediation": "N/A"
        })
    else:
        findings.append({
            "control": "SSH enabled",
            "status": "FAIL",
            "severity": "MEDIUM",
            "reason": "SSH protocol v2 is not explicitly configured for remote administration.",
            "remediation": "ip ssh version 2"
        })

    # 4. Password Policy
    password_match = re.search(
        r"^security\s+passwords\s+min-length\s+(\d+)\b",
        full_text,
        re.MULTILINE
    )

    if password_match:
        min_length = int(password_match.group(1))

        if min_length >= 12:
            findings.append({
                "control": "Minimum password length configured",
                "status": "PASS",
                "severity": "MEDIUM",
                "reason": f"Minimum password length is configured to {min_length} characters.",
                "remediation": "N/A"
            })
        else:
            findings.append({
                "control": "Minimum password length configured",
                "status": "FAIL",
                "severity": "MEDIUM",
                "reason": f"Minimum password length is only {min_length} characters. At least 12 characters are required.",
                "remediation": "security passwords min-length 12"
            })
    else:
        findings.append({
            "control": "Minimum password length configured",
            "status": "FAIL",
            "severity": "MEDIUM",
            "reason": "Minimum password length policy is not configured.",
            "remediation": "security passwords min-length 12"
        })

    # Calculate Compliance Score
    passed = sum(
        1 for finding in findings
        if finding["status"] == "PASS"
    )

    score = round((passed / len(findings)) * 100)

    return {
        "vendor": "Cisco IOS",
        "compliance": score,
        "findings": findings
    }

  
# ================================
# JUNIPER JUNOS ANALYZER ENGINE
# ================================
def evaluate_juniper(config_text: str):
    findings = []
    lines = [l.strip().lower() for l in config_text.splitlines() if l.strip()]

    # 1. Telnet Disabled
    has_telnet = any("set system services telnet" in l for l in lines)
    if has_telnet:
        findings.append({
            "control": "Telnet disabled",
            "status": "FAIL",
            "severity": "HIGH",
            "reason": "Telnet service is explicitly active in Junos configuration.",
            "remediation": "delete system services telnet"
        })
    else:
        findings.append({
            "control": "Telnet disabled",
            "status": "PASS",
            "severity": "HIGH",
            "reason": "Telnet daemon is not enabled on the system.",
            "remediation": "N/A"
        })

    # 2. HTTP Web-Management Disabled
    has_http = any("set system services web-management http" in l for l in lines)
    if has_http:
        findings.append({
            "control": "HTTP web-management disabled",
            "status": "FAIL",
            "severity": "HIGH",
            "reason": "Unencrypted HTTP web management interface is enabled.",
            "remediation": "delete system services web-management http"
        })
    else:
        findings.append({
            "control": "HTTP web-management disabled",
            "status": "PASS",
            "severity": "HIGH",
            "reason": "Insecure HTTP web-management is disabled.",
            "remediation": "N/A"
        })

    # 3. SSH Service Enabled
    has_ssh = any("set system services ssh" in l for l in lines)
    if has_ssh:
        findings.append({
            "control": "SSH enabled",
            "status": "PASS",
            "severity": "MEDIUM",
            "reason": "Encrypted Junos SSH remote management daemon is running.",
            "remediation": "N/A"
        })
    else:
        findings.append({
            "control": "SSH enabled",
            "status": "FAIL",
            "severity": "MEDIUM",
            "reason": "SSH service is absent. Management interface is inaccessible or insecure.",
            "remediation": "set system services ssh"
        })

    # 4. Remote Syslog Logging
    has_syslog = any("set system syslog host" in l for l in lines)
    if has_syslog:
        findings.append({
            "control": "Remote logging enabled",
            "status": "PASS",
            "severity": "MEDIUM",
            "reason": "Centralized SIEM/Syslog export host is configured.",
            "remediation": "N/A"
        })
    else:
        findings.append({
            "control": "Remote logging enabled",
            "status": "FAIL",
            "severity": "MEDIUM",
            "reason": "No remote syslog host configured. Audit logs remain vulnerable to tampering.",
            "remediation": "set system syslog host <syslog-ip>"
        })

    score = round((sum(1 for f in findings if f["status"] == "PASS") / len(findings)) * 100)
    return {"vendor": "Juniper Junos", "compliance": score, "findings": findings}

@app.post("/analyze/cisco")
def analyze_cisco_endpoint(payload: ConfigPayload):
    return evaluate_cisco(payload.config)

@app.post("/analyze/juniper")
def analyze_juniper_endpoint(payload: ConfigPayload):
    return evaluate_juniper(payload.config)


# ================================
# Automatic Vendor Detection
# ================================
def detect_vendor(config_text: str):
    text = config_text.lower()

    # Cisco IOS indicators
    cisco_patterns = [
        r"^hostname\s+",
        r"^interface\s+\S+",
        r"^line\s+vty",
        r"^ip\s+ssh\s+version",
        r"^transport\s+input",
        r"^no\s+ip\s+http\s+server"
    ]

    # Juniper Junos indicators
    juniper_patterns = [
        r"^set\s+system\s+",
        r"^set\s+interfaces\s+",
        r"^set\s+security\s+",
        r"^set\s+firewall\s+",
        r"^set\s+routing-options\s+"
    ]

    cisco_score = sum(
        1 for pattern in cisco_patterns
        if re.search(pattern, text, re.MULTILINE)
    )

    juniper_score = sum(
        1 for pattern in juniper_patterns
        if re.search(pattern, text, re.MULTILINE)
    )

    if cisco_score > juniper_score and cisco_score > 0:
        return "cisco", "Cisco IOS", cisco_score

    if juniper_score > cisco_score and juniper_score > 0:
        return "juniper", "Juniper Junos", juniper_score

    return "unknown", "Unknown / Unsupported", 0

@app.post("/analyze/auto")
def analyze_auto(payload: ConfigPayload):
    vendor, vendor_name, confidence_score = detect_vendor(payload.config)

    if vendor == "cisco":
        result = evaluate_cisco(payload.config)

    elif vendor == "juniper":
        result = evaluate_juniper(payload.config)

    else:
        return {
            "vendor": vendor_name,
            "confidence": "Low",
            "compliance": 0,
            "findings": [],
            "message": "Unable to identify a supported network vendor."
        }

    result["detected_vendor"] = vendor_name
    result["detection_score"] = confidence_score
    result["confidence"] = (
        "High" if confidence_score >= 2
        else "Medium"
    )

    return result