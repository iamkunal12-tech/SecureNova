def analyze_cisco_config(config_text):
    findings = []

    config_lower = config_text.lower()

    # Rule 1: Telnet should be disabled
    telnet_enabled = "transport input telnet" in config_lower

    findings.append({
        "control": "Telnet disabled",
        "status": "FAIL" if telnet_enabled else "PASS",
        "severity": "HIGH",
        "reason": (
            "Telnet is enabled. Telnet sends credentials without secure encryption."
            if telnet_enabled
            else "Telnet is not enabled."
        ),
        "remediation": (
            "Remove Telnet access and use SSH."
            if telnet_enabled
            else ""
        )
    })

    # Rule 2: HTTP should be disabled
    http_enabled = (
        "ip http server" in config_lower
        and "no ip http server" not in config_lower
    )

    findings.append({
        "control": "HTTP disabled",
        "status": "FAIL" if http_enabled else "PASS",
        "severity": "HIGH",
        "reason": (
            "HTTP management service is enabled. HTTPS should be preferred."
            if http_enabled
            else "HTTP management service is disabled."
        ),
        "remediation": (
            "no ip http server"
            if http_enabled
            else ""
        )
    })

    # Rule 3: SSH should be enabled
    ssh_enabled = (
        "transport input ssh" in config_lower
        or "ip ssh version" in config_lower
    )

    findings.append({
        "control": "SSH enabled",
        "status": "PASS" if ssh_enabled else "FAIL",
        "severity": "MEDIUM",
        "reason": (
            "Secure SSH access is configured."
            if ssh_enabled
            else "SSH configuration was not detected."
        ),
        "remediation": (
            ""
            if ssh_enabled
            else "Configure SSH for secure remote management."
        )
    })

    # Rule 4: Password minimum length
    password_policy = "security passwords min-length"

    password_configured = password_policy in config_lower

    findings.append({
        "control": "Minimum password length configured",
        "status": "PASS" if password_configured else "FAIL",
        "severity": "MEDIUM",
        "reason": (
            "Password minimum length policy is configured."
            if password_configured
            else "Password minimum length policy was not detected."
        ),
        "remediation": (
            ""
            if password_configured
            else "security passwords min-length 12"
        )
    })

    return findings


def calculate_compliance(findings):
    total = len(findings)

    passed = sum(
        1 for finding in findings
        if finding["status"] == "PASS"
    )

    if total == 0:
        return 0

    return round((passed / total) * 100, 2)
