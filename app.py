import json
import os
import re
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from google import genai


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    gemini_client = genai.Client(api_key=GEMINI_API_KEY)
else:
    gemini_client = None


app = FastAPI(
    title="SecureNova AI API - SIH26155",
    version="1.2.0",
    description="AI-Driven Multi-Vendor Network Security Compliance Auditor"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATA MODELS
# ============================================================

class ConfigPayload(BaseModel):
    config: str


class DeviceAnalyzePayload(BaseModel):
    name: str
    config: str


class BatchConfigPayload(BaseModel):
    config: str


# ============================================================
# DATABASE / DEMO DATA
# ============================================================

def get_data_path() -> str:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "demo_data.json")


def load_demo_data() -> list:
    json_path = get_data_path()

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

            if isinstance(data, list):
                return data

            return []

    except FileNotFoundError:
        return []

    except json.JSONDecodeError:
        return []


DEVICES = load_demo_data()


def save_demo_data() -> None:
    json_path = get_data_path()

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            DEVICES,
            f,
            indent=2,
            ensure_ascii=False
        )


# ============================================================
# SECURITY STATUS
# ============================================================

def get_device_status(compliance: int) -> str:
    """
    Compliance thresholds:

    90-100 -> green
    70-89  -> yellow
    0-69   -> red
    """

    if compliance >= 90:
        return "green"

    if compliance >= 70:
        return "yellow"

    return "red"


# ============================================================
# ROOT / HEALTH
# ============================================================

@app.get("/")
def root():
    return {
        "name": "SecureNova",
        "problem_id": "SIH26155",
        "status": "online",
        "message": "SecureNova AI Network Security Compliance API"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "devices": len(DEVICES),
        "gemini_configured": gemini_client is not None
    }


# ============================================================
# DEVICE ENDPOINTS
# ============================================================

@app.get("/devices")
def get_devices():

    for device in DEVICES:

        compliance = int(
            device.get("compliance", 0)
        )

        device["status"] = get_device_status(
            compliance
        )

    return DEVICES


@app.get("/devices/{device_id}")
def get_device(device_id: int):

    for device in DEVICES:

        if int(device.get("id", 0)) == device_id:

            compliance = int(
                device.get("compliance", 0)
            )

            device["status"] = get_device_status(
                compliance
            )

            return device

    raise HTTPException(
        status_code=404,
        detail="Device not found."
    )


# ============================================================
# SUMMARY
# ============================================================

@app.get("/summary")
def get_summary():

    total_devices = len(DEVICES)

    if total_devices == 0:

        return {
            "total_devices": 0,
            "compliant_devices": 0,
            "warning_devices": 0,
            "critical_devices": 0,
            "average_compliance": 0
        }

    compliant_devices = 0
    warning_devices = 0
    critical_devices = 0

    compliance_values = []

    for device in DEVICES:

        compliance = int(
            device.get("compliance", 0)
        )

        compliance_values.append(
            compliance
        )

        status = get_device_status(
            compliance
        )

        if status == "green":

            compliant_devices += 1

        elif status == "yellow":

            warning_devices += 1

        else:

            critical_devices += 1

    average_compliance = round(
        sum(compliance_values) / total_devices
    )

    return {
        "total_devices": total_devices,
        "compliant_devices": compliant_devices,
        "warning_devices": warning_devices,
        "critical_devices": critical_devices,
        "average_compliance": average_compliance
    }


# ============================================================
# CISCO IOS ANALYZER
# ============================================================

def evaluate_cisco(config_text: str) -> dict:

    config = config_text.lower()

    findings = []

    # --------------------------------------------------------
    # RULE 1: TELNET
    # --------------------------------------------------------

    telnet_enabled = bool(
        re.search(
            r"transport\s+input\s+(?:.*\btelnet\b.*|\btelnet\b)",
            config,
            re.IGNORECASE
        )
        or
        re.search(
            r"transport\s+input\s+all\b",
            config,
            re.IGNORECASE
        )
    )

    if telnet_enabled:

        findings.append({
            "title": "Telnet Disabled",
            "status": "FAIL",
            "severity": "High",
            "reason": "Telnet is enabled on the VTY lines.",
            "recommended_config": "no transport input telnet"
        })

    else:

        findings.append({
            "title": "Telnet Disabled",
            "status": "PASS",
            "severity": "Low",
            "reason": "Telnet access is disabled.",
            "recommended_config": "no transport input telnet"
        })

    # --------------------------------------------------------
    # RULE 2: HTTP SERVER
    # --------------------------------------------------------

    http_enabled = bool(
        re.search(
            r"^\s*ip\s+http\s+server\b",
            config,
            re.MULTILINE | re.IGNORECASE
        )
    )

    if http_enabled:

        findings.append({
            "title": "HTTP Server Disabled",
            "status": "FAIL",
            "severity": "High",
            "reason": "The Cisco HTTP server is enabled.",
            "recommended_config": "no ip http server"
        })

    else:

        findings.append({
            "title": "HTTP Server Disabled",
            "status": "PASS",
            "severity": "Low",
            "reason": "Cisco HTTP server is disabled.",
            "recommended_config": "no ip http server"
        })

    # --------------------------------------------------------
    # RULE 3: SSH
    # --------------------------------------------------------

    ssh_enabled = bool(
        re.search(
            r"\bip\s+ssh\s+version\s+2\b",
            config,
            re.IGNORECASE
        )
        or
        re.search(
            r"\btransport\s+input\s+ssh\b",
            config,
            re.IGNORECASE
        )
    )

    if ssh_enabled:

        findings.append({
            "title": "SSH Enabled",
            "status": "PASS",
            "severity": "Low",
            "reason": "SSH version 2 or SSH-only VTY access is enabled.",
            "recommended_config": "ip ssh version 2"
        })

    else:

        findings.append({
            "title": "SSH Enabled",
            "status": "FAIL",
            "severity": "High",
            "reason": "Secure SSH access is not properly enabled.",
            "recommended_config": "ip ssh version 2"
        })

    # --------------------------------------------------------
    # RULE 4: PASSWORD LENGTH
    # --------------------------------------------------------

    password_match = re.search(
        r"security\s+passwords\s+min-length\s+(\d+)",
        config,
        re.IGNORECASE
    )

    if password_match:

        minimum_length = int(
            password_match.group(1)
        )

        if minimum_length >= 12:

            findings.append({
                "title": "Minimum Password Length",
                "status": "PASS",
                "severity": "Low",
                "reason": (
                    f"Minimum password length is "
                    f"{minimum_length} characters."
                ),
                "recommended_config": (
                    "security passwords min-length 12"
                )
            })

        else:

            findings.append({
                "title": "Minimum Password Length",
                "status": "FAIL",
                "severity": "Medium",
                "reason": (
                    f"Minimum password length is "
                    f"{minimum_length}, which is below "
                    "the required 12 characters."
                ),
                "recommended_config": (
                    "security passwords min-length 12"
                )
            })

    else:

        findings.append({
            "title": "Minimum Password Length",
            "status": "FAIL",
            "severity": "Medium",
            "reason": (
                "Minimum password length is not configured."
            ),
            "recommended_config": (
                "security passwords min-length 12"
            )
        })

    # --------------------------------------------------------
    # SCORE
    # --------------------------------------------------------

    passed = sum(
        1
        for finding in findings
        if finding["status"] == "PASS"
    )

    total = len(findings)

    compliance = (
        round((passed / total) * 100)
        if total
        else 0
    )

    return {
        "vendor": "Cisco IOS",
        "compliance": compliance,
        "findings": findings
    }


# ============================================================
# JUNIPER JUNOS ANALYZER
# ============================================================

def evaluate_juniper(config_text: str) -> dict:

    config = config_text.lower()

    findings = []

    # --------------------------------------------------------
    # RULE 1: TELNET
    # --------------------------------------------------------

    telnet_enabled = bool(
        re.search(
            r"^\s*set\s+system\s+services\s+telnet\b",
            config,
            re.MULTILINE | re.IGNORECASE
        )
    )

    if telnet_enabled:

        findings.append({
            "title": "Telnet Disabled",
            "status": "FAIL",
            "severity": "High",
            "reason": "Juniper Telnet service is enabled.",
            "recommended_config": (
                "delete system services telnet"
            )
        })

    else:

        findings.append({
            "title": "Telnet Disabled",
            "status": "PASS",
            "severity": "Low",
            "reason": "Telnet service is disabled.",
            "recommended_config": (
                "delete system services telnet"
            )
        })

    # --------------------------------------------------------
    # RULE 2: HTTP MANAGEMENT
    # --------------------------------------------------------

    http_enabled = bool(
        re.search(
            r"^\s*set\s+system\s+services\s+web-management\s+http\b",
            config,
            re.MULTILINE | re.IGNORECASE
        )
    )

    if http_enabled:

        findings.append({
            "title": "HTTP Web Management Disabled",
            "status": "FAIL",
            "severity": "High",
            "reason": "HTTP web management is enabled.",
            "recommended_config": (
                "delete system services "
                "web-management http"
            )
        })

    else:

        findings.append({
            "title": "HTTP Web Management Disabled",
            "status": "PASS",
            "severity": "Low",
            "reason": "HTTP web management is disabled.",
            "recommended_config": (
                "delete system services "
                "web-management http"
            )
        })

    # --------------------------------------------------------
    # RULE 3: SSH
    # --------------------------------------------------------

    ssh_enabled = bool(
        re.search(
            r"^\s*set\s+system\s+services\s+ssh\b",
            config,
            re.MULTILINE | re.IGNORECASE
        )
    )

    if ssh_enabled:

        findings.append({
            "title": "SSH Enabled",
            "status": "PASS",
            "severity": "Low",
            "reason": "Juniper SSH service is enabled.",
            "recommended_config": (
                "set system services ssh"
            )
        })

    else:

        findings.append({
            "title": "SSH Enabled",
            "status": "FAIL",
            "severity": "High",
            "reason": (
                "Juniper SSH service is not enabled."
            ),
            "recommended_config": (
                "set system services ssh"
            )
        })

    # --------------------------------------------------------
    # RULE 4: REMOTE LOGGING
    # --------------------------------------------------------

    remote_logging = bool(
        re.search(
            r"^\s*set\s+system\s+syslog\s+host\b",
            config,
            re.MULTILINE | re.IGNORECASE
        )
    )

    if remote_logging:

        findings.append({
            "title": "Remote Logging",
            "status": "PASS",
            "severity": "Low",
            "reason": (
                "Remote syslog configuration is enabled."
            ),
            "recommended_config": (
                "set system syslog host "
                "<syslog-server>"
            )
        })

    else:

        findings.append({
            "title": "Remote Logging",
            "status": "FAIL",
            "severity": "Medium",
            "reason": (
                "Remote syslog configuration is missing."
            ),
            "recommended_config": (
                "set system syslog host "
                "<syslog-server>"
            )
        })

    # --------------------------------------------------------
    # SCORE
    # --------------------------------------------------------

    passed = sum(
        1
        for finding in findings
        if finding["status"] == "PASS"
    )

    total = len(findings)

    compliance = (
        round((passed / total) * 100)
        if total
        else 0
    )

    return {
        "vendor": "Juniper Junos",
        "compliance": compliance,
        "findings": findings
    }


# ============================================================
# VENDOR DETECTION
# ============================================================

def detect_vendor(config_text: str):

    config = config_text.lower()

    # --------------------------------------------------------
    # CISCO PATTERNS
    # --------------------------------------------------------

    cisco_patterns = [
        r"^\s*hostname\s+\S+",
        r"^\s*interface\s+\S+",
        r"^\s*line\s+vty\b",
        r"\bip\s+ssh\s+version\b",
        r"\btransport\s+input\b",
        r"\bip\s+http\s+server\b",
        r"\bno\s+ip\s+http\s+server\b",
        r"\bsecurity\s+passwords\s+min-length\b"
    ]

    # --------------------------------------------------------
    # JUNIPER PATTERNS
    # --------------------------------------------------------

    juniper_patterns = [
        r"^\s*set\s+system\b",
        r"^\s*set\s+interfaces\b",
        r"^\s*set\s+security\b",
        r"^\s*set\s+firewall\b",
        r"^\s*set\s+routing-options\b",
        r"^\s*set\s+protocols\b"
    ]

    cisco_score = sum(
        1
        for pattern in cisco_patterns
        if re.search(
            pattern,
            config,
            re.MULTILINE | re.IGNORECASE
        )
    )

    juniper_score = sum(
        1
        for pattern in juniper_patterns
        if re.search(
            pattern,
            config,
            re.MULTILINE | re.IGNORECASE
        )
    )

    # --------------------------------------------------------
    # UNKNOWN
    # --------------------------------------------------------

    if cisco_score == 0 and juniper_score == 0:

        return (
            "unknown",
            "Unknown / Unsupported",
            0
        )

    # --------------------------------------------------------
    # CISCO
    # --------------------------------------------------------

    if cisco_score > juniper_score:

        confidence = round(
            (cisco_score / len(cisco_patterns)) * 100
        )

        return (
            "cisco",
            "Cisco IOS",
            confidence
        )

    # --------------------------------------------------------
    # JUNIPER
    # --------------------------------------------------------

    if juniper_score > cisco_score:

        confidence = round(
            (juniper_score / len(juniper_patterns)) * 100
        )

        return (
            "juniper",
            "Juniper Junos",
            confidence
        )

    # --------------------------------------------------------
    # AMBIGUOUS
    # --------------------------------------------------------

    return (
        "unknown",
        "Unknown / Ambiguous",
        50
    )


# ============================================================
# MULTI-DEVICE CONFIGURATION PARSER
# ============================================================

def split_multi_device_config(config_text: str) -> list:

    """
    Expected format:

    DEVICE: Device-Name
    VENDOR: Cisco

    configuration...

    DEVICE: Another-Device
    VENDOR: Juniper

    configuration...
    """

    pattern = r"(?im)^\s*DEVICE:\s*(.+?)\s*$"

    matches = list(
        re.finditer(
            pattern,
            config_text
        )
    )

    if not matches:
        return []

    devices = []

    for index, match in enumerate(matches):

        device_name = match.group(1).strip()

        start = match.end()

        if index + 1 < len(matches):

            end = matches[index + 1].start()

        else:

            end = len(config_text)

        block = config_text[
            start:end
        ].strip()

        # Remove optional VENDOR line

        block = re.sub(
            r"(?im)^\s*VENDOR:\s*.*?$",
            "",
            block
        ).strip()

        if not block:
            continue

        devices.append({
            "name": device_name,
            "config": block
        })

    return devices


# ============================================================
# CISCO DIRECT ANALYSIS
# ============================================================

@app.post("/analyze/cisco")
def analyze_cisco(payload: ConfigPayload):

    config = payload.config.strip()

    if not config:

        raise HTTPException(
            status_code=400,
            detail="Configuration cannot be empty."
        )

    result = evaluate_cisco(config)

    return {
        "status": "success",
        **result
    }


# ============================================================
# JUNIPER DIRECT ANALYSIS
# ============================================================

@app.post("/analyze/juniper")
def analyze_juniper(payload: ConfigPayload):

    config = payload.config.strip()

    if not config:

        raise HTTPException(
            status_code=400,
            detail="Configuration cannot be empty."
        )

    result = evaluate_juniper(config)

    return {
        "status": "success",
        **result
    }


# ============================================================
# AUTOMATIC ANALYSIS
# ============================================================

@app.post("/analyze/auto")
def analyze_auto(payload: ConfigPayload):

    config = payload.config.strip()

    if not config:

        raise HTTPException(
            status_code=400,
            detail="Configuration cannot be empty."
        )

    vendor, detected_vendor, confidence = detect_vendor(
        config
    )

    if vendor == "unknown":

        return {
            "status": "error",
            "message": (
                "Unable to identify a supported "
                "network vendor."
            ),
            "vendor": detected_vendor,
            "confidence": confidence
        }

    # --------------------------------------------------------
    # DETERMINISTIC RULE ENGINE
    # --------------------------------------------------------

    if vendor == "cisco":

        result = evaluate_cisco(config)

    else:

        result = evaluate_juniper(config)

    # --------------------------------------------------------
    # AI REMEDIATION
    # --------------------------------------------------------

    ai_remediation = generate_ai_remediation(
        result["vendor"],
        result["compliance"],
        result["findings"]
    )

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return {
        "status": "success",
        "vendor": result["vendor"],
        "compliance": result["compliance"],
        "security_status": get_device_status(
            result["compliance"]
        ),
        "findings": result["findings"],
        "detection": {
            "vendor": detected_vendor,
            "score": confidence,
            "confidence": (
                "High"
                if confidence >= 70
                else "Medium"
                if confidence >= 40
                else "Low"
            )
        },
        "ai_remediation": ai_remediation
    }


# ============================================================
# ANALYZE + REGISTER SINGLE DEVICE
# ============================================================

@app.post("/devices/analyze")
def analyze_and_register_device(
    payload: DeviceAnalyzePayload
):

    name = payload.name.strip()
    config = payload.config.strip()

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    if not name:

        raise HTTPException(
            status_code=400,
            detail="Device name is required."
        )

    if not config:

        raise HTTPException(
            status_code=400,
            detail="Configuration is required."
        )

    # --------------------------------------------------------
    # VENDOR DETECTION
    # --------------------------------------------------------

    vendor, detected_vendor, confidence = detect_vendor(
        config
    )

    if vendor == "unknown":

        return {
            "status": "error",
            "message": (
                "Unable to identify a supported vendor. "
                "Please provide Cisco IOS or "
                "Juniper Junos configuration."
            ),
            "vendor": detected_vendor,
            "confidence": confidence
        }

    # --------------------------------------------------------
    # ANALYZE
    # --------------------------------------------------------

    if vendor == "cisco":

        analysis = evaluate_cisco(config)
        normalized_vendor = "Cisco"

    else:

        analysis = evaluate_juniper(config)
        normalized_vendor = "Juniper"

    compliance = int(
        analysis["compliance"]
    )

    device_status = get_device_status(
        compliance
    )

    # --------------------------------------------------------
    # AI REMEDIATION
    # --------------------------------------------------------

    ai_remediation = generate_ai_remediation(
        analysis["vendor"],
        compliance,
        analysis["findings"]
    )

    # --------------------------------------------------------
    # CHECK EXISTING DEVICE
    # --------------------------------------------------------

    existing_device = next(
        (
            device
            for device in DEVICES
            if device.get("name", "").strip().lower()
            == name.lower()
        ),
        None
    )

    # --------------------------------------------------------
    # UPDATE EXISTING
    # --------------------------------------------------------

    if existing_device:

        existing_device["vendor"] = normalized_vendor
        existing_device["compliance"] = compliance
        existing_device["status"] = device_status
        existing_device["findings"] = analysis["findings"]

        device = existing_device
        action = "updated"

    # --------------------------------------------------------
    # ADD NEW
    # --------------------------------------------------------

    else:

        next_id = max(
            (
                int(device.get("id", 0))
                for device in DEVICES
            ),
            default=0
        ) + 1

        device = {
            "id": next_id,
            "name": name,
            "vendor": normalized_vendor,
            "compliance": compliance,
            "status": device_status,
            "findings": analysis["findings"]
        }

        DEVICES.append(device)

        action = "added"

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    save_demo_data()

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return {
        "status": "success",
        "action": action,
        "message": f"Device {action} successfully.",
        "device": device,
        "detected_vendor": detected_vendor,
        "confidence": confidence,
        "ai_remediation": ai_remediation
    }


# ============================================================
# BATCH MULTI-DEVICE ANALYSIS
# ============================================================

@app.post("/devices/batch-analyze")
def batch_analyze_devices(
    payload: BatchConfigPayload
):

    config_text = payload.config.strip()

    if not config_text:

        raise HTTPException(
            status_code=400,
            detail="Configuration file cannot be empty."
        )

    # --------------------------------------------------------
    # SPLIT FILE INTO DEVICES
    # --------------------------------------------------------

    device_configs = split_multi_device_config(
        config_text
    )

    if not device_configs:

        raise HTTPException(
            status_code=400,
            detail=(
                "No devices found. Use the format "
                "'DEVICE: Device-Name'."
            )
        )

    results = []

    added = 0
    updated = 0
    failed = 0

    # --------------------------------------------------------
    # PROCESS EVERY DEVICE
    # --------------------------------------------------------

    for item in device_configs:

        name = item["name"].strip()
        config = item["config"].strip()

        if not name or not config:

            failed += 1

            results.append({
                "name": name,
                "status": "error",
                "message": (
                    "Device name or configuration "
                    "is missing."
                )
            })

            continue

        # ----------------------------------------------------
        # VENDOR DETECTION
        # ----------------------------------------------------

        vendor, detected_vendor, confidence = detect_vendor(
            config
        )

        if vendor == "unknown":

            failed += 1

            results.append({
                "name": name,
                "status": "error",
                "message": (
                    "Unable to identify supported vendor."
                ),
                "vendor": detected_vendor,
                "confidence": confidence
            })

            continue

        # ----------------------------------------------------
        # SECURITY ANALYSIS
        # ----------------------------------------------------

        if vendor == "cisco":

            analysis = evaluate_cisco(config)
            normalized_vendor = "Cisco"

        else:

            analysis = evaluate_juniper(config)
            normalized_vendor = "Juniper"

        compliance = int(
            analysis["compliance"]
        )

        device_status = get_device_status(
            compliance
        )

        # ----------------------------------------------------
        # AI REMEDIATION
        # ----------------------------------------------------

        ai_remediation = generate_ai_remediation(
            analysis["vendor"],
            compliance,
            analysis["findings"]
        )

        # ----------------------------------------------------
        # FIND EXISTING DEVICE
        # ----------------------------------------------------

        existing_device = next(
            (
                device
                for device in DEVICES
                if device.get("name", "").strip().lower()
                == name.lower()
            ),
            None
        )

        # ----------------------------------------------------
        # UPDATE
        # ----------------------------------------------------

        if existing_device:

            existing_device["vendor"] = normalized_vendor
            existing_device["compliance"] = compliance
            existing_device["status"] = device_status
            existing_device["findings"] = analysis["findings"]

            device = existing_device
            action = "updated"

            updated += 1

        # ----------------------------------------------------
        # ADD
        # ----------------------------------------------------

        else:

            next_id = max(
                (
                    int(device.get("id", 0))
                    for device in DEVICES
                ),
                default=0
            ) + 1

            device = {
                "id": next_id,
                "name": name,
                "vendor": normalized_vendor,
                "compliance": compliance,
                "status": device_status,
                "findings": analysis["findings"]
            }

            DEVICES.append(device)

            action = "added"

            added += 1

        # ----------------------------------------------------
        # STORE RESULT
        # ----------------------------------------------------

        results.append({
            "name": name,
            "status": "success",
            "action": action,
            "vendor": normalized_vendor,
            "detected_vendor": detected_vendor,
            "confidence": confidence,
            "compliance": compliance,
            "security_status": device_status,
            "findings": analysis["findings"],
            "ai_remediation": ai_remediation
        })

    # --------------------------------------------------------
    # SAVE ALL DEVICES
    # --------------------------------------------------------

    save_demo_data()

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return {
        "status": "success",
        "message": (
            f"Batch analysis completed. "
            f"{added} added, "
            f"{updated} updated, "
            f"{failed} failed."
        ),
        "total_processed": len(device_configs),
        "added": added,
        "updated": updated,
        "failed": failed,
        "devices": results
    }


# ============================================================
# GEMINI CONNECTION TEST
# ============================================================

@app.get("/test-gemini")
def test_gemini():

    if not gemini_client:

        return {
            "status": "error",
            "message": (
                "GEMINI_API_KEY is not configured."
            )
        }

    try:

        response = gemini_client.models.generate_content(
            model="gemini-3.6-flash",
            contents=(
                "Reply with exactly: "
                "SecureNova Gemini connection successful."
            )
        )

        return {
            "status": "success",
            "message": response.text
        }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }


# ============================================================
# GEMINI AI REMEDIATION
# ============================================================

def generate_ai_remediation(
    vendor: str,
    compliance: int,
    findings: list
) -> dict:

    # --------------------------------------------------------
    # GEMINI NOT CONFIGURED
    # --------------------------------------------------------

    if not gemini_client:

        return {
            "status": "unavailable",
            "message": (
                "Gemini is not configured. "
                "Deterministic compliance analysis "
                "is still available."
            ),
            "recommendations": []
        }

    # --------------------------------------------------------
    # FAILED FINDINGS
    # --------------------------------------------------------

    failed_findings = [
        finding
        for finding in findings
        if str(
            finding.get("status", "")
        ).upper() == "FAIL"
    ]

    # --------------------------------------------------------
    # EVERYTHING PASSED
    # --------------------------------------------------------

    if not failed_findings:

        return {
            "status": "success",
            "recommendations": [
                {
                    "priority": "Low",
                    "title": "Configuration is compliant",
                    "explanation": (
                        "No major compliance failures "
                        "were detected."
                    ),
                    "action": (
                        "Continue periodic configuration "
                        "auditing."
                    )
                }
            ]
        }

    # --------------------------------------------------------
    # PREPARE AI INPUT
    # --------------------------------------------------------

    findings_text = json.dumps(
        failed_findings,
        indent=2,
        ensure_ascii=False
    )

    prompt = f"""
You are a network security compliance assistant.

Vendor:
{vendor}

Current compliance:
{compliance}%

The following security controls failed:

{findings_text}

Generate practical remediation recommendations.

Return ONLY valid JSON.

Use exactly this structure:

{{
  "recommendations": [
    {{
      "priority": "High",
      "title": "Short title",
      "explanation": "Short explanation",
      "action": "Specific remediation action"
    }}
  ]
}}

Rules:
- Do not use Markdown.
- Do not include code fences.
- Do not invent security findings.
- Only provide recommendations related to the supplied failures.
- Keep recommendations practical and concise.
"""

    # --------------------------------------------------------
    # GEMINI REQUEST
    # --------------------------------------------------------

    try:

        response = gemini_client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt
        )

        raw_text = (
            response.text.strip()
            if response.text
            else ""
        )

        # ----------------------------------------------------
        # CLEAN MARKDOWN CODE FENCES
        # ----------------------------------------------------

        raw_text = re.sub(
            r"^```json\s*",
            "",
            raw_text,
            flags=re.IGNORECASE
        )

        raw_text = re.sub(
            r"^```\s*",
            "",
            raw_text
        )

        raw_text = re.sub(
            r"\s*```$",
            "",
            raw_text
        )

        # ----------------------------------------------------
        # PARSE JSON
        # ----------------------------------------------------

        parsed = json.loads(
            raw_text
        )

        recommendations = parsed.get(
            "recommendations",
            []
        )

        if not isinstance(
            recommendations,
            list
        ):

            recommendations = []

        return {
            "status": "success",
            "recommendations": recommendations
        }

    except json.JSONDecodeError:

        return {
            "status": "error",
            "message": (
                "Gemini returned an invalid JSON response."
            ),
            "recommendations": []
        }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e),
            "recommendations": []
        }
