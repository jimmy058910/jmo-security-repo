#!/usr/bin/env python3
"""
Compliance framework mapping module for JMo Security Audit Tool Suite.

Maps security findings (by tool, ruleId, CWE, severity) to compliance frameworks:
- OWASP Top 10 2021
- CWE Top 25 2024
- CIS Controls v8.1
- NIST Cybersecurity Framework 2.0
- PCI DSS 4.0
- MITRE ATT&CK v16.1

Usage:
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = {...}  # CommonFinding dict
    enriched = enrich_finding_with_compliance(finding)
    # enriched["compliance"] now contains all framework mappings
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# =============================================================================
# CWE Top 25 2024 Most Dangerous Software Weaknesses
# =============================================================================

CWE_TOP_25_2024 = {
    "CWE-79": {
        "rank": 1,
        "category": "Injection",
        "name": "Cross-site Scripting (XSS)",
    },
    "CWE-787": {"rank": 2, "category": "Memory Safety", "name": "Out-of-bounds Write"},
    "CWE-89": {"rank": 3, "category": "Injection", "name": "SQL Injection"},
    "CWE-20": {
        "rank": 4,
        "category": "Input Validation",
        "name": "Improper Input Validation",
    },
    "CWE-78": {"rank": 5, "category": "Injection", "name": "OS Command Injection"},
    "CWE-125": {"rank": 6, "category": "Memory Safety", "name": "Out-of-bounds Read"},
    "CWE-416": {"rank": 7, "category": "Memory Safety", "name": "Use After Free"},
    "CWE-22": {"rank": 8, "category": "Path Traversal", "name": "Path Traversal"},
    "CWE-352": {"rank": 9, "category": "CSRF", "name": "Cross-Site Request Forgery"},
    "CWE-434": {
        "rank": 10,
        "category": "File Upload",
        "name": "Unrestricted Upload of Dangerous File Type",
    },
    "CWE-862": {
        "rank": 11,
        "category": "Access Control",
        "name": "Missing Authorization",
    },
    "CWE-476": {
        "rank": 12,
        "category": "Null Pointer",
        "name": "NULL Pointer Dereference",
    },
    "CWE-287": {
        "rank": 13,
        "category": "Authentication",
        "name": "Improper Authentication",
    },
    "CWE-190": {"rank": 14, "category": "Integer Overflow", "name": "Integer Overflow"},
    "CWE-502": {
        "rank": 15,
        "category": "Deserialization",
        "name": "Insecure Deserialization",
    },
    "CWE-77": {"rank": 16, "category": "Injection", "name": "Command Injection"},
    "CWE-119": {"rank": 17, "category": "Memory Safety", "name": "Buffer Overflow"},
    "CWE-798": {
        "rank": 18,
        "category": "Credentials",
        "name": "Use of Hard-coded Credentials",
    },
    "CWE-918": {
        "rank": 19,
        "category": "SSRF",
        "name": "Server-Side Request Forgery (SSRF)",
    },
    "CWE-306": {
        "rank": 20,
        "category": "Authentication",
        "name": "Missing Authentication",
    },
    "CWE-362": {"rank": 21, "category": "Race Condition", "name": "Race Condition"},
    "CWE-269": {
        "rank": 22,
        "category": "Privilege Management",
        "name": "Improper Privilege Management",
    },
    "CWE-94": {"rank": 23, "category": "Code Injection", "name": "Code Injection"},
    "CWE-863": {
        "rank": 24,
        "category": "Authorization",
        "name": "Incorrect Authorization",
    },
    "CWE-276": {
        "rank": 25,
        "category": "Permissions",
        "name": "Incorrect Default Permissions",
    },
}

# =============================================================================
# OWASP Top 10 2021 Mappings
# =============================================================================

# Maps CWEs to OWASP Top 10 2021 categories
CWE_TO_OWASP_TOP10_2021 = {
    # A01:2021 - Broken Access Control
    "CWE-22": ["A01:2021"],  # Path Traversal
    "CWE-269": ["A01:2021"],  # Improper Privilege Management
    "CWE-276": ["A01:2021"],  # Incorrect Default Permissions
    "CWE-284": ["A01:2021"],  # Improper Access Control
    "CWE-285": ["A01:2021"],  # Improper Authorization
    "CWE-352": ["A01:2021"],  # CSRF
    "CWE-359": ["A01:2021"],  # Exposure of Private Information
    "CWE-434": ["A01:2021"],  # Unrestricted File Upload
    "CWE-639": ["A01:2021"],  # Authorization Bypass
    "CWE-706": ["A01:2021"],  # Incorrect Object-Level Authorization
    "CWE-862": ["A01:2021"],  # Missing Authorization
    "CWE-863": ["A01:2021"],  # Incorrect Authorization
    # A02:2021 - Cryptographic Failures
    "CWE-259": ["A02:2021"],  # Use of Hard-coded Password
    "CWE-261": ["A02:2021"],  # Weak Cryptography for Passwords
    "CWE-295": [
        "A02:2021",
        "A07:2021",
    ],  # Improper Certificate Validation (crypto + auth)
    "CWE-297": ["A02:2021"],  # Improper Validation of Certificate
    "CWE-310": ["A02:2021"],  # Cryptographic Issues
    "CWE-311": ["A02:2021"],  # Missing Encryption of Sensitive Data
    "CWE-312": ["A02:2021"],  # Cleartext Storage of Sensitive Information
    "CWE-319": ["A02:2021"],  # Cleartext Transmission
    "CWE-321": ["A02:2021"],  # Use of Hard-coded Cryptographic Key
    "CWE-322": ["A02:2021"],  # Key Exchange without Entity Authentication
    "CWE-323": ["A02:2021"],  # Reusing a Nonce
    "CWE-324": ["A02:2021"],  # Use of a Key Past its Expiration Date
    "CWE-325": ["A02:2021"],  # Missing Required Cryptographic Step
    "CWE-326": ["A02:2021"],  # Inadequate Encryption Strength
    "CWE-327": ["A02:2021"],  # Use of Broken Cryptographic Algorithm
    "CWE-328": ["A02:2021"],  # Reversible One-Way Hash
    "CWE-329": ["A02:2021"],  # Not Using Random IV
    "CWE-330": ["A02:2021"],  # Insufficient Randomness
    "CWE-331": ["A02:2021"],  # Insufficient Entropy
    "CWE-335": [
        "A02:2021"
    ],  # Incorrect Usage of Seeds in Pseudo-Random Number Generator
    "CWE-338": ["A02:2021"],  # Use of Weak Pseudo-Random Number Generator
    "CWE-759": ["A02:2021"],  # Use of a One-Way Hash without a Salt
    "CWE-798": ["A02:2021"],  # Use of Hard-coded Credentials
    "CWE-916": [
        "A02:2021"
    ],  # Use of Password Hash with Insufficient Computational Effort
    # A03:2021 - Injection
    "CWE-20": ["A03:2021"],  # Improper Input Validation
    "CWE-77": ["A03:2021"],  # Command Injection
    "CWE-78": ["A03:2021"],  # OS Command Injection
    "CWE-79": ["A03:2021"],  # XSS
    "CWE-88": ["A03:2021"],  # Argument Injection
    "CWE-89": ["A03:2021"],  # SQL Injection
    "CWE-90": ["A03:2021"],  # LDAP Injection
    "CWE-91": ["A03:2021"],  # XML Injection
    "CWE-93": ["A03:2021"],  # CRLF Injection
    "CWE-94": ["A03:2021"],  # Code Injection
    "CWE-95": ["A03:2021"],  # Eval Injection
    "CWE-96": ["A03:2021"],  # Server-Side Include Injection
    "CWE-97": ["A03:2021"],  # Server-Side Template Injection
    "CWE-99": ["A03:2021"],  # Resource Injection
    "CWE-917": ["A03:2021"],  # Expression Language Injection
    # A04:2021 - Insecure Design
    "CWE-209": ["A04:2021"],  # Information Exposure Through Error Messages
    "CWE-256": ["A04:2021"],  # Plaintext Storage of Password
    "CWE-257": ["A04:2021"],  # Storing Passwords in Recoverable Format
    "CWE-522": ["A04:2021"],  # Insufficiently Protected Credentials
    "CWE-525": ["A04:2021"],  # Information Exposure Through Browser Caching
    # A05:2021 - Security Misconfiguration
    "CWE-2": ["A05:2021"],  # Environmental Security Flaws
    "CWE-11": ["A05:2021"],  # ASP.NET Misconfiguration
    "CWE-13": ["A05:2021"],  # ASP.NET Misconfiguration
    "CWE-15": ["A05:2021"],  # External Control of System Configuration
    "CWE-16": ["A05:2021"],  # Configuration
    "CWE-260": ["A05:2021"],  # Password in Configuration File
    "CWE-315": ["A05:2021"],  # Cleartext Storage in Cookie
    "CWE-520": ["A05:2021"],  # .NET Misconfiguration
    "CWE-526": ["A05:2021"],  # Information Exposure Through Environmental Variables
    "CWE-537": ["A05:2021"],  # Information Exposure Through Java Runtime Error Message
    "CWE-541": ["A05:2021"],  # Information Exposure Through Include Source Code
    "CWE-548": ["A05:2021"],  # Information Exposure Through Directory Listing
    "CWE-611": ["A05:2021"],  # XML External Entity (XXE)
    "CWE-732": ["A05:2021"],  # Incorrect Permission Assignment
    "CWE-942": ["A05:2021"],  # Permissive Cross-domain Policy
    # A06:2021 - Vulnerable and Outdated Components
    "CWE-1104": ["A06:2021"],  # Use of Unmaintained Third-Party Components
    "CWE-1035": ["A06:2021"],  # 2021 CWE Top 25
    "CWE-1329": ["A06:2021"],  # Reliance on Component That is Not Updateable
    # A07:2021 - Identification and Authentication Failures
    "CWE-287": ["A07:2021"],  # Improper Authentication
    "CWE-288": ["A07:2021"],  # Authentication Bypass Using Alternate Path
    "CWE-290": ["A07:2021"],  # Authentication Bypass by Spoofing
    "CWE-294": ["A07:2021"],  # Authentication Bypass by Capture-replay
    "CWE-300": ["A07:2021"],  # Channel Accessible by Non-Endpoint
    "CWE-302": ["A07:2021"],  # Authentication Bypass by Assumed-Immutable Data
    "CWE-303": ["A07:2021"],  # Incorrect Implementation of Authentication Algorithm
    "CWE-304": ["A07:2021"],  # Missing Critical Step in Authentication
    "CWE-306": ["A07:2021"],  # Missing Authentication
    "CWE-307": [
        "A07:2021"
    ],  # Improper Restriction of Excessive Authentication Attempts
    "CWE-346": ["A07:2021"],  # Origin Validation Error
    "CWE-384": ["A07:2021"],  # Session Fixation
    "CWE-521": ["A07:2021"],  # Weak Password Requirements
    "CWE-613": ["A07:2021"],  # Insufficient Session Expiration
    "CWE-620": ["A07:2021"],  # Unverified Password Change
    "CWE-640": ["A07:2021"],  # Weak Password Recovery
    # A08:2021 - Software and Data Integrity Failures
    "CWE-345": ["A08:2021"],  # Insufficient Verification of Data Authenticity
    "CWE-353": ["A08:2021"],  # Missing Support for Integrity Check
    "CWE-426": ["A08:2021"],  # Untrusted Search Path
    "CWE-494": ["A08:2021"],  # Download of Code Without Integrity Check
    "CWE-502": ["A08:2021"],  # Insecure Deserialization
    "CWE-565": ["A08:2021"],  # Reliance on Cookies without Validation
    "CWE-829": ["A08:2021"],  # Inclusion of Functionality from Untrusted Control Sphere
    "CWE-830": ["A08:2021"],  # Inclusion of Web Functionality from Untrusted Source
    "CWE-915": [
        "A08:2021"
    ],  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
    # A09:2021 - Security Logging and Monitoring Failures
    "CWE-117": ["A09:2021"],  # Improper Output Neutralization for Logs
    "CWE-223": ["A09:2021"],  # Omission of Security-relevant Information
    "CWE-532": ["A09:2021"],  # Information Exposure Through Log Files
    "CWE-778": ["A09:2021"],  # Insufficient Logging
    # A10:2021 - Server-Side Request Forgery (SSRF)
    "CWE-918": ["A10:2021"],  # Server-Side Request Forgery
}

# Tool-specific rule mappings to OWASP
TOOL_RULE_TO_OWASP_TOP10_2021 = {
    "trufflehog": {
        # All secrets findings map to A02:2021
        "*": ["A02:2021"],
    },
    "semgrep": {
        "generic.secrets.gitleaks.*": ["A02:2021"],
        "generic.secrets.*": ["A02:2021"],
        "generic.html-templates.*": ["A03:2021"],
        "javascript.express.security.*": ["A05:2021"],
        "python.django.security.*": ["A05:2021"],
        "python.lang.security.audit.exec-use": ["A03:2021"],
        "python.lang.security.audit.subprocess-shell-true": ["A03:2021"],
        "javascript.lang.security.audit.eval-use": ["A03:2021"],
    },
    "trivy": {
        # CVE findings map based on CWE
        "*": None,  # Use CWE mapping
    },
    "checkov": {
        "CKV_AWS_*": ["A05:2021"],  # Cloud misconfigurations
        "CKV_AZURE_*": ["A05:2021"],
        "CKV_GCP_*": ["A05:2021"],
        "CKV_K8S_*": ["A05:2021"],
        "CKV_DOCKER_*": ["A05:2021"],
    },
    "bandit": {
        "B201": ["A03:2021"],  # Flask debug mode
        "B301": ["A08:2021"],  # Pickle usage
        "B302": ["A08:2021"],  # Marshal usage
        "B303": ["A02:2021"],  # MD5 usage
        "B304": ["A02:2021"],  # Insecure cipher
        "B305": ["A02:2021"],  # Insecure cipher mode
        "B306": ["A02:2021"],  # Insecure temporary file
        "B307": ["A03:2021"],  # Eval usage
        "B308": ["A02:2021"],  # Mark_safe usage
        "B309": ["A05:2021"],  # HTTPSConnection
        "B310": ["A05:2021"],  # URLopen
        "B311": ["A02:2021"],  # Pseudo-random
        "B312": ["A02:2021"],  # Telnet usage
        "B313": ["A03:2021"],  # XML bad parser
        "B314": ["A03:2021"],  # XML bad parser
        "B315": ["A03:2021"],  # XML bad parser
        "B316": ["A03:2021"],  # XML bad parser
        "B317": ["A03:2021"],  # XML bad parser
        "B318": ["A03:2021"],  # XML etree
        "B319": ["A03:2021"],  # XML sax
        "B320": ["A03:2021"],  # XML lxml
        "B321": ["A03:2021"],  # FTP usage
        "B323": ["A05:2021"],  # Unverified SSL/TLS
        "B324": ["A02:2021"],  # Insecure hash
        "B401": ["A03:2021"],  # Shell injection
        "B602": ["A03:2021"],  # Shell=True
        "B603": ["A03:2021"],  # Subprocess without shell check
        "B604": ["A03:2021"],  # Function call with shell=True
        "B605": ["A03:2021"],  # Shell injection (start_process)
        "B606": ["A03:2021"],  # Shell injection (no_shell)
        "B607": ["A03:2021"],  # Partial path
        "B608": ["A03:2021"],  # SQL injection
        "B609": ["A03:2021"],  # Wildcard injection
    },
    "zap": {
        "10010": ["A03:2021"],  # XSS
        "10012": ["A03:2021"],  # Script in comments
        "10015": ["A05:2021"],  # Re-examine cache
        "10017": ["A05:2021"],  # Cross-domain misconfiguration
        "10019": ["A05:2021"],  # Content-Type missing
        "10020": ["A05:2021"],  # X-Frame-Options missing
        "10021": ["A05:2021"],  # X-Content-Type-Options missing
        "10023": ["A07:2021"],  # Information disclosure
        "10024": ["A07:2021"],  # Information disclosure - database
        "10025": ["A07:2021"],  # Information disclosure - sensitive
        "10027": ["A09:2021"],  # Information disclosure - referrer
        "10028": ["A05:2021"],  # Open redirect
        "10029": ["A05:2021"],  # Cookie missing secure flag
        "10030": ["A07:2021"],  # User controllable charset
        "10031": ["A07:2021"],  # User controllable HTML
        "10032": ["A05:2021"],  # Viewstate without MAC
        "10033": ["A05:2021"],  # Directory browsing
        "10034": ["A05:2021"],  # Heartbleed
        "10035": ["A05:2021"],  # Strict-Transport-Security missing
        "10036": ["A05:2021"],  # HTTP Server Response Header
        "10037": ["A05:2021"],  # Server leaks information
        "10038": ["A05:2021"],  # Content Security Policy missing
        "10039": ["A05:2021"],  # X-Backend-Server header
        "10040": ["A05:2021"],  # Secure pages browser cache
        "10041": ["A07:2021"],  # HTTP Parameter Pollution
        "10042": ["A05:2021"],  # Spring Actuator info leak
        "10043": ["A05:2021"],  # User controllable JS event
        "10044": ["A05:2021"],  # Big redirect response
        "10045": ["A05:2021"],  # Source code disclosure
        "10046": ["A05:2021"],  # Nginx reverse proxy cache
        "10047": ["A05:2021"],  # HTTPS content available via HTTP
        "10048": ["A05:2021"],  # Remote code execution
        "10049": ["A05:2021"],  # Content cacheability
        "10050": ["A05:2021"],  # Retrieved from cache
        "10051": ["A05:2021"],  # Relative path confusion
        "10052": ["A05:2021"],  # X-ChromeLogger-Data header
        "10053": ["A05:2021"],  # Apache Range Header DoS
        "10054": ["A05:2021"],  # Cookie without SameSite
        "10055": ["A05:2021"],  # CSP scanner
        "10056": ["A05:2021"],  # X-Debug-Token leak
        "10057": ["A05:2021"],  # Username hash found
        "10058": ["A05:2021"],  # GET for POST
        "10061": ["A05:2021"],  # X-AspNet-Version header
        "10062": ["A05:2021"],  # PII disclosure
        "10095": ["A05:2021"],  # Backup file disclosure
        "10096": ["A05:2021"],  # Timestamp disclosure
        "10097": ["A05:2021"],  # Hash disclosure
        "10098": ["A05:2021"],  # Cross-domain JavaScript source
        "10099": ["A05:2021"],  # Source code disclosure
        "10101": ["A05:2021"],  # Unexpected Content-Type
        "10102": ["A05:2021"],  # Unexpected response code
        "20012": ["A07:2021"],  # Anti-CSRF tokens scanner
        "20014": ["A07:2021"],  # HTTP Parameter Pollution
        "20015": ["A05:2021"],  # Heartbleed
        "20016": ["A07:2021"],  # Cross-domain misconfiguration
        "20017": ["A05:2021"],  # Source code disclosure
        "20018": ["A07:2021"],  # Remote file inclusion
        "30001": ["A05:2021"],  # Buffer overflow
        "30002": ["A03:2021"],  # Format string error
        "30003": ["A03:2021"],  # Integer overflow error
        "40003": ["A10:2021"],  # CRLF injection
        "40008": ["A03:2021"],  # Parameter tampering
        "40009": ["A10:2021"],  # Server-side include
        "40012": ["A01:2021"],  # Cross-Site Request Forgery
        "40013": ["A01:2021"],  # Session fixation
        "40014": ["A01:2021"],  # Cross-site scripting
        "40016": ["A03:2021"],  # Cross-site scripting (persistent)
        "40017": ["A03:2021"],  # Cross-site scripting (reflected)
        "40018": ["A03:2021"],  # SQL injection
        "40019": ["A03:2021"],  # SQL injection (Hypersonic)
        "40020": ["A03:2021"],  # SQL injection (Oracle)
        "40021": ["A03:2021"],  # SQL injection (PostgreSQL)
        "40022": ["A03:2021"],  # SQL injection (MySQL)
        "40023": ["A03:2021"],  # NoSQL injection (MongoDB)
        "40024": ["A03:2021"],  # Generic padding oracle
        "40025": ["A03:2021"],  # Expression language injection
        "40026": ["A03:2021"],  # Cross-site scripting (DOM)
        "40027": ["A03:2021"],  # SQL injection (SQLite)
        "40028": ["A03:2021"],  # ELMAH information leak
        "40029": ["A05:2021"],  # Trace.axd information leak
        "40030": ["A05:2021"],  # CORS misconfiguration
        "40031": ["A05:2021"],  # POODLE
        "40032": ["A02:2021"],  # SSL/TLS weak cipher
        "40033": ["A03:2021"],  # LDAP injection
        "40034": ["A03:2021"],  # .NET padding oracle
        "40035": ["A05:2021"],  # Hidden file finder
        "40036": ["A05:2021"],  # Java serialization object
        "40037": ["A03:2021"],  # Remote file inclusion
        "40038": ["A05:2021"],  # Weak authentication method
        "40039": ["A05:2021"],  # Insecure component
        "40040": ["A10:2021"],  # CORS bypass via XSS
        "40041": ["A03:2021"],  # FileUpload XSS
        "40042": ["A05:2021"],  # Spring Actuator exploit
        "40043": ["A03:2021"],  # Log4Shell
        "40044": ["A08:2021"],  # Insecure YAML deserialization
        "40045": ["A03:2021"],  # Server-side template injection
        "90001": ["A09:2021"],  # Insecure JSF ViewState
        "90011": ["A05:2021"],  # Charset mismatch
        "90017": ["A05:2021"],  # XSLT injection
        "90019": ["A05:2021"],  # Server-side code injection
        "90020": ["A03:2021"],  # Remote OS command injection
        "90021": ["A03:2021"],  # XPath injection
        "90022": ["A03:2021"],  # Application error disclosure
        "90023": ["A03:2021"],  # XML external entity attack
        "90024": ["A05:2021"],  # Generic padding oracle
        "90025": ["A05:2021"],  # Expression language injection
        "90026": ["A05:2021"],  # SOAP action spoofing
        "90027": ["A05:2021"],  # Cookie slack detector
        "90028": ["A07:2021"],  # Insecure HTTP method
        "90029": ["A05:2021"],  # Base64 disclosure
        "90030": ["A05:2021"],  # WSDL file disclosure
        "90033": ["A05:2021"],  # Loosely scoped cookie
        "90034": ["A05:2021"],  # Cloud metadata attack
        "100000": ["A05:2021"],  # A Remotely Accessible Config File
    },
}

# =============================================================================
# CIS Controls v8.1 Mappings
# =============================================================================

# Maps tool/finding types to CIS Controls v8.1
CIS_CONTROLS_V8_1 = {
    "secrets": [
        {
            "control": "3.11",
            "title": "Encrypt Sensitive Data at Rest",
            "implementationGroup": "IG1",
        },
        {
            "control": "5.4",
            "title": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
            "implementationGroup": "IG1",
        },
    ],
    "sast": [
        {
            "control": "16.2",
            "title": "Establish and Maintain a Secure Application Development Process",
            "implementationGroup": "IG1",
        },
        {
            "control": "16.5",
            "title": "Use Up-to-Date and Trusted Third-Party Software Components",
            "implementationGroup": "IG2",
        },
        {
            "control": "16.7",
            "title": "Use Standard Hardening Configuration Templates for Application Infrastructure",
            "implementationGroup": "IG2",
        },
        {
            "control": "16.11",
            "title": "Leverage Vetted Modules or Services for Application Security Components",
            "implementationGroup": "IG2",
        },
    ],
    "sca": [
        {
            "control": "7.1",
            "title": "Establish and Maintain a Vulnerability Management Process",
            "implementationGroup": "IG1",
        },
        {
            "control": "7.2",
            "title": "Establish and Maintain a Remediation Process",
            "implementationGroup": "IG1",
        },
        {
            "control": "7.3",
            "title": "Perform Automated Operating System Patch Management",
            "implementationGroup": "IG1",
        },
        {
            "control": "7.4",
            "title": "Perform Automated Application Patch Management",
            "implementationGroup": "IG2",
        },
        {
            "control": "16.11",
            "title": "Leverage Vetted Modules or Services for Application Security Components",
            "implementationGroup": "IG2",
        },
    ],
    "iac": [
        {
            "control": "4.1",
            "title": "Establish and Maintain a Secure Configuration Process",
            "implementationGroup": "IG1",
        },
        {
            "control": "4.2",
            "title": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
            "implementationGroup": "IG1",
        },
        {
            "control": "4.7",
            "title": "Manage Default Accounts on Enterprise Assets and Software",
            "implementationGroup": "IG1",
        },
        {
            "control": "12.4",
            "title": "Deny Communication over Unauthorized Ports",
            "implementationGroup": "IG1",
        },
    ],
    "dast": [
        {
            "control": "16.13",
            "title": "Conduct Application Penetration Testing",
            "implementationGroup": "IG2",
        },
        {
            "control": "18.3",
            "title": "Remediate Penetration Test Findings",
            "implementationGroup": "IG2",
        },
    ],
    "container": [
        {
            "control": "4.1",
            "title": "Establish and Maintain a Secure Configuration Process",
            "implementationGroup": "IG1",
        },
        {
            "control": "4.7",
            "title": "Manage Default Accounts on Enterprise Assets and Software",
            "implementationGroup": "IG1",
        },
    ],
    "runtime": [
        {"control": "8.2", "title": "Collect Audit Logs", "implementationGroup": "IG1"},
        {
            "control": "8.5",
            "title": "Collect Detailed Audit Logs",
            "implementationGroup": "IG2",
        },
    ],
}

# =============================================================================
# NIST Cybersecurity Framework 2.0 Mappings
# =============================================================================

# Maps tool/finding types to NIST CSF 2.0
NIST_CSF_2_0 = {
    "secrets": [
        {
            "function": "PROTECT",
            "category": "PR.DS",
            "subcategory": "PR.DS-1",
            "description": "Data-at-rest is protected",
        },
        {
            "function": "PROTECT",
            "category": "PR.AC",
            "subcategory": "PR.AC-1",
            "description": "Identities and credentials are issued, managed, verified, revoked, and audited",
        },
    ],
    "sast": [
        {
            "function": "DETECT",
            "category": "DE.CM",
            "subcategory": "DE.CM-8",
            "description": "Vulnerability scans are performed",
        },
        {
            "function": "IDENTIFY",
            "category": "ID.RA",
            "subcategory": "ID.RA-1",
            "description": "Asset vulnerabilities are identified and documented",
        },
    ],
    "sca": [
        {
            "function": "IDENTIFY",
            "category": "ID.RA",
            "subcategory": "ID.RA-1",
            "description": "Asset vulnerabilities are identified and documented",
        },
        {
            "function": "GOVERN",
            "category": "GV.SC",
            "subcategory": "GV.SC-3",
            "description": "Cybersecurity supply chain risk management processes are identified, established, assessed, managed, and agreed upon by organizational stakeholders",
        },
    ],
    "iac": [
        {
            "function": "PROTECT",
            "category": "PR.IP",
            "subcategory": "PR.IP-1",
            "description": "A baseline configuration of information technology systems is created and maintained",
        },
        {
            "function": "PROTECT",
            "category": "PR.PT",
            "subcategory": "PR.PT-3",
            "description": "The principle of least functionality is incorporated",
        },
    ],
    "dast": [
        {
            "function": "DETECT",
            "category": "DE.CM",
            "subcategory": "DE.CM-8",
            "description": "Vulnerability scans are performed",
        },
    ],
}

# Maps CWEs to NIST CSF 2.0
CWE_TO_NIST_CSF_2_0 = {
    "CWE-798": [
        {
            "function": "PROTECT",
            "category": "PR.AC",
            "subcategory": "PR.AC-1",
            "description": "Identities and credentials are issued, managed, verified, revoked, and audited",
        },
        {
            "function": "PROTECT",
            "category": "PR.DS",
            "subcategory": "PR.DS-1",
            "description": "Data-at-rest is protected",
        },
    ],
    "CWE-259": [
        {
            "function": "PROTECT",
            "category": "PR.AC",
            "subcategory": "PR.AC-1",
            "description": "Identities and credentials are issued, managed, verified, revoked, and audited",
        },
    ],
    "CWE-327": [
        {
            "function": "PROTECT",
            "category": "PR.DS",
            "subcategory": "PR.DS-2",
            "description": "Data-in-transit is protected",
        },
    ],
    "CWE-79": [
        {
            "function": "DETECT",
            "category": "DE.CM",
            "subcategory": "DE.CM-8",
            "description": "Vulnerability scans are performed",
        },
    ],
    "CWE-89": [
        {
            "function": "DETECT",
            "category": "DE.CM",
            "subcategory": "DE.CM-8",
            "description": "Vulnerability scans are performed",
        },
    ],
    "CWE-1104": [
        {
            "function": "GOVERN",
            "category": "GV.SC",
            "subcategory": "GV.SC-3",
            "description": "Cybersecurity supply chain risk management processes are identified",
        },
    ],
}

# =============================================================================
# PCI DSS 4.0 Mappings
# =============================================================================

# Maps finding types to PCI DSS 4.0 requirements
PCI_DSS_4_0 = {
    "secrets": [
        {
            "requirement": "8.3.2",
            "description": "Strong cryptography is used to render authentication credentials unreadable during transmission and storage",
            "priority": "CRITICAL",
        },
        {
            "requirement": "8.2.1",
            "description": "User identity is verified before modifying authentication credentials",
            "priority": "HIGH",
        },
    ],
    "sast": [
        {
            "requirement": "6.2.4",
            "description": "Bespoke and custom software are developed securely (attacks prevented)",
            "priority": "CRITICAL",
        },
        {
            "requirement": "6.3.2",
            "description": "An inventory of bespoke and custom software is maintained",
            "priority": "HIGH",
        },
    ],
    "sca": [
        {
            "requirement": "6.3.3",
            "description": "Security vulnerabilities are identified and managed",
            "priority": "CRITICAL",
        },
        {
            "requirement": "11.3.1",
            "description": "Internal vulnerability scans are performed",
            "priority": "HIGH",
        },
    ],
    "iac": [
        {
            "requirement": "1.2.1",
            "description": "Configuration standards for NSCs are defined",
            "priority": "HIGH",
        },
        {
            "requirement": "2.2.1",
            "description": "Configuration standards are defined for system components",
            "priority": "HIGH",
        },
    ],
    "dast": [
        {
            "requirement": "11.3.2",
            "description": "External vulnerability scans are performed",
            "priority": "HIGH",
        },
    ],
}

# Maps CWEs to PCI DSS 4.0
CWE_TO_PCI_DSS_4_0 = {
    "CWE-798": [
        {
            "requirement": "8.3.2",
            "description": "Strong cryptography for authentication credentials",
            "priority": "CRITICAL",
        },
        {
            "requirement": "8.2.1",
            "description": "Verify user identity before credential modification",
            "priority": "HIGH",
        },
    ],
    "CWE-259": [
        {
            "requirement": "8.3.2",
            "description": "Strong cryptography for authentication credentials",
            "priority": "CRITICAL",
        },
    ],
    "CWE-327": [
        {
            "requirement": "4.2.1",
            "description": "Strong cryptography is used for PAN transmission",
            "priority": "CRITICAL",
        },
    ],
    "CWE-79": [
        {
            "requirement": "6.2.4",
            "description": "Prevent XSS attacks in bespoke software",
            "priority": "CRITICAL",
        },
    ],
    "CWE-89": [
        {
            "requirement": "6.2.4",
            "description": "Prevent SQL injection attacks in bespoke software",
            "priority": "CRITICAL",
        },
    ],
    "CWE-352": [
        {
            "requirement": "6.2.4",
            "description": "Prevent CSRF attacks in bespoke software",
            "priority": "CRITICAL",
        },
    ],
}

# =============================================================================
# MITRE ATT&CK v16.1 Mappings
# =============================================================================

# Maps tool/finding types to MITRE ATT&CK techniques
MITRE_ATTACK = {
    "secrets": [
        {
            "tactic": "Credential Access",
            "technique": "T1552",
            "techniqueName": "Unsecured Credentials",
            "subtechnique": "T1552.001",
            "subtechniqueName": "Credentials in Files",
        },
        {
            "tactic": "Initial Access",
            "technique": "T1078",
            "techniqueName": "Valid Accounts",
            "subtechnique": "",
            "subtechniqueName": "",
        },
    ],
    "sast_injection": [
        {
            "tactic": "Execution",
            "technique": "T1059",
            "techniqueName": "Command and Scripting Interpreter",
            "subtechnique": "T1059.001",
            "subtechniqueName": "PowerShell",
        },
        {
            "tactic": "Initial Access",
            "technique": "T1190",
            "techniqueName": "Exploit Public-Facing Application",
            "subtechnique": "",
            "subtechniqueName": "",
        },
    ],
    "sca": [
        {
            "tactic": "Initial Access",
            "technique": "T1195",
            "techniqueName": "Supply Chain Compromise",
            "subtechnique": "T1195.001",
            "subtechniqueName": "Compromise Software Dependencies and Development Tools",
        },
    ],
    "container": [
        {
            "tactic": "Privilege Escalation",
            "technique": "T1611",
            "techniqueName": "Escape to Host",
            "subtechnique": "",
            "subtechniqueName": "",
        },
        {
            "tactic": "Execution",
            "technique": "T1610",
            "techniqueName": "Deploy Container",
            "subtechnique": "",
            "subtechniqueName": "",
        },
    ],
    "runtime": [
        {
            "tactic": "Defense Evasion",
            "technique": "T1562",
            "techniqueName": "Impair Defenses",
            "subtechnique": "T1562.001",
            "subtechniqueName": "Disable or Modify Tools",
        },
    ],
}

# Maps CWEs to MITRE ATT&CK
CWE_TO_MITRE_ATTACK = {
    "CWE-798": [
        {
            "tactic": "Credential Access",
            "technique": "T1552",
            "techniqueName": "Unsecured Credentials",
            "subtechnique": "T1552.001",
            "subtechniqueName": "Credentials in Files",
        },
    ],
    "CWE-259": [
        {
            "tactic": "Credential Access",
            "technique": "T1552",
            "techniqueName": "Unsecured Credentials",
            "subtechnique": "T1552.001",
            "subtechniqueName": "Credentials in Files",
        },
    ],
    "CWE-79": [
        {
            "tactic": "Initial Access",
            "technique": "T1190",
            "techniqueName": "Exploit Public-Facing Application",
            "subtechnique": "",
            "subtechniqueName": "",
        },
    ],
    "CWE-89": [
        {
            "tactic": "Initial Access",
            "technique": "T1190",
            "techniqueName": "Exploit Public-Facing Application",
            "subtechnique": "",
            "subtechniqueName": "",
        },
    ],
    "CWE-78": [
        {
            "tactic": "Execution",
            "technique": "T1059",
            "techniqueName": "Command and Scripting Interpreter",
            "subtechnique": "",
            "subtechniqueName": "",
        },
    ],
    "CWE-1104": [
        {
            "tactic": "Initial Access",
            "technique": "T1195",
            "techniqueName": "Supply Chain Compromise",
            "subtechnique": "T1195.001",
            "subtechniqueName": "Compromise Software Dependencies",
        },
    ],
}

# =============================================================================
# Enrichment Functions
# =============================================================================


def get_tool_category(tool_name: str, tags: List[str]) -> Optional[str]:
    """Determine tool category for framework mapping.

    Args:
        tool_name: Name of the security tool (e.g., "trufflehog", "semgrep")
        tags: List of tags from the finding

    Returns:
        Category string: "secrets", "sast", "sca", "iac", "dast", "container", "runtime" or None
    """
    tool = tool_name.lower()

    # Secrets scanners
    if tool in ["trufflehog", "gitleaks", "noseyparker"] or "secrets" in tags:
        return "secrets"

    # SAST tools
    if tool in ["semgrep", "bandit"] or "sast" in tags:
        return "sast"

    # SCA/vulnerability tools
    if tool in ["trivy", "syft", "osv-scanner"] or "sca" in tags or "vuln" in tags:
        return "sca"

    # IaC scanners
    if tool in ["checkov", "tfsec", "hadolint"] or "iac" in tags:
        return "iac"

    # DAST tools
    if tool in ["zap"] or "dast" in tags:
        return "dast"

    # Container security
    if "container" in tags or "docker" in tags:
        return "container"

    # Runtime security
    if tool in ["falco", "afl++"] or "runtime" in tags:
        return "runtime"

    return None


def map_cwe_to_owasp_top10_2021(cwes: List[str]) -> List[str]:
    """Map CWE IDs to OWASP Top 10 2021 categories.

    Args:
        cwes: List of CWE IDs (e.g., ["CWE-79", "CWE-89"])

    Returns:
        List of OWASP Top 10 2021 categories (e.g., ["A03:2021"])
    """
    owasp_categories = set()

    for cwe in cwes:
        cwe_clean = cwe.upper().strip()
        if cwe_clean in CWE_TO_OWASP_TOP10_2021:
            owasp_categories.update(CWE_TO_OWASP_TOP10_2021[cwe_clean])

    return sorted(list(owasp_categories))


def map_cwe_to_top25_2024(cwes: List[str]) -> List[Dict[str, Any]]:
    """Map CWE IDs to CWE Top 25 2024 with rank and category.

    Args:
        cwes: List of CWE IDs (e.g., ["CWE-79", "CWE-89"])

    Returns:
        List of CWE Top 25 entries with id, rank, category
    """
    top25_entries = []

    for cwe in cwes:
        cwe_clean = cwe.upper().strip()
        if cwe_clean in CWE_TOP_25_2024:
            top25_entries.append(
                {
                    "id": cwe_clean,
                    "rank": CWE_TOP_25_2024[cwe_clean]["rank"],
                    "category": CWE_TOP_25_2024[cwe_clean]["category"],
                }
            )

    # Sort by rank
    top25_entries.sort(key=lambda x: x["rank"])
    return top25_entries


def map_to_cis_controls_v8_1(tool_name: str, tags: List[str]) -> List[Dict[str, str]]:
    """Map finding to CIS Controls v8.1.

    Args:
        tool_name: Name of the security tool
        tags: List of tags from the finding

    Returns:
        List of CIS Controls with control, title, implementationGroup
    """
    category = get_tool_category(tool_name, tags)
    if category and category in CIS_CONTROLS_V8_1:
        return CIS_CONTROLS_V8_1[category]
    return []


def map_to_nist_csf_2_0(
    tool_name: str, tags: List[str], cwes: List[str]
) -> List[Dict[str, str]]:
    """Map finding to NIST CSF 2.0.

    Args:
        tool_name: Name of the security tool
        tags: List of tags from the finding
        cwes: List of CWE IDs

    Returns:
        List of NIST CSF 2.0 mappings with function, category, subcategory, description
    """
    mappings = []

    # First try CWE-specific mappings
    for cwe in cwes:
        cwe_clean = cwe.upper().strip()
        if cwe_clean in CWE_TO_NIST_CSF_2_0:
            mappings.extend(CWE_TO_NIST_CSF_2_0[cwe_clean])

    # Then try category-based mappings
    category = get_tool_category(tool_name, tags)
    if category and category in NIST_CSF_2_0:
        mappings.extend(NIST_CSF_2_0[category])

    # Deduplicate by subcategory
    seen = set()
    unique_mappings = []
    for m in mappings:
        key = m.get("subcategory", "")
        if key not in seen:
            seen.add(key)
            unique_mappings.append(m)

    return unique_mappings


def map_to_pci_dss_4_0(
    tool_name: str, tags: List[str], cwes: List[str]
) -> List[Dict[str, str]]:
    """Map finding to PCI DSS 4.0 requirements.

    Args:
        tool_name: Name of the security tool
        tags: List of tags from the finding
        cwes: List of CWE IDs

    Returns:
        List of PCI DSS 4.0 mappings with requirement, description, priority
    """
    mappings = []

    # First try CWE-specific mappings
    for cwe in cwes:
        cwe_clean = cwe.upper().strip()
        if cwe_clean in CWE_TO_PCI_DSS_4_0:
            mappings.extend(CWE_TO_PCI_DSS_4_0[cwe_clean])

    # Then try category-based mappings
    category = get_tool_category(tool_name, tags)
    if category and category in PCI_DSS_4_0:
        mappings.extend(PCI_DSS_4_0[category])

    # Deduplicate by requirement
    seen = set()
    unique_mappings = []
    for m in mappings:
        key = m.get("requirement", "")
        if key not in seen:
            seen.add(key)
            unique_mappings.append(m)

    return unique_mappings


def map_to_mitre_attack(
    tool_name: str, tags: List[str], cwes: List[str], rule_id: str
) -> List[Dict[str, str]]:
    """Map finding to MITRE ATT&CK techniques.

    Args:
        tool_name: Name of the security tool
        tags: List of tags from the finding
        cwes: List of CWE IDs
        rule_id: Rule ID from the finding

    Returns:
        List of MITRE ATT&CK mappings with tactic, technique, techniqueName, subtechnique, subtechniqueName
    """
    mappings = []

    # First try CWE-specific mappings
    for cwe in cwes:
        cwe_clean = cwe.upper().strip()
        if cwe_clean in CWE_TO_MITRE_ATTACK:
            mappings.extend(CWE_TO_MITRE_ATTACK[cwe_clean])

    # Then try category-based mappings
    category = get_tool_category(tool_name, tags)

    # Special case for injection findings
    if category == "sast" and any(
        inj in rule_id.lower() for inj in ["inject", "xss", "sql", "command", "eval"]
    ):
        category = "sast_injection"

    if category and category in MITRE_ATTACK:
        mappings.extend(MITRE_ATTACK[category])

    # Deduplicate by technique
    seen = set()
    unique_mappings = []
    for m in mappings:
        key = m.get("technique", "")
        if key not in seen:
            seen.add(key)
            unique_mappings.append(m)

    return unique_mappings


def map_rule_to_owasp_top10_2021(tool_name: str, rule_id: str) -> List[str]:
    """Map tool-specific rule ID to OWASP Top 10 2021.

    Args:
        tool_name: Name of the security tool
        rule_id: Rule ID from the finding

    Returns:
        List of OWASP Top 10 2021 categories
    """
    tool = tool_name.lower()

    if tool not in TOOL_RULE_TO_OWASP_TOP10_2021:
        return []

    tool_mappings = TOOL_RULE_TO_OWASP_TOP10_2021[tool]

    # Check for exact match
    if rule_id in tool_mappings:
        mapping = tool_mappings[rule_id]
        return mapping if mapping else []

    # Check for pattern match
    for pattern, mapping in tool_mappings.items():
        if pattern == "*":
            continue
        if "*" in pattern:
            # Glob-style pattern matching
            prefix = pattern.split("*")[0]
            if rule_id.startswith(prefix):
                return mapping if mapping else []

    # Check for wildcard match
    if "*" in tool_mappings and tool_mappings["*"]:
        return tool_mappings["*"]

    return []


def enrich_finding_with_compliance(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich a CommonFinding with compliance framework mappings.

    This function adds the "compliance" field to a CommonFinding dict, mapping the finding
    to OWASP Top 10, CWE Top 25, CIS Controls, NIST CSF, PCI DSS, and MITRE ATT&CK.

    Args:
        finding: CommonFinding dictionary (v1.1.0 or v1.2.0)

    Returns:
        Enriched finding with "compliance" field populated
    """
    # Extract fields needed for mapping
    tool_info = finding.get("tool", {})
    tool_name = tool_info.get("name", "") if isinstance(tool_info, dict) else ""
    rule_id = finding.get("ruleId", "")
    tags = finding.get("tags", [])

    # Extract CWEs from risk.cwe or risk metadata
    risk = finding.get("risk", {})
    cwes = risk.get("cwe", []) if isinstance(risk, dict) else []

    # Initialize compliance dict
    compliance = {}

    # OWASP Top 10 2021
    owasp_categories = set()

    # Map from CWEs
    if cwes:
        owasp_categories.update(map_cwe_to_owasp_top10_2021(cwes))

    # Map from tool-specific rules
    rule_owasp = map_rule_to_owasp_top10_2021(tool_name, rule_id)
    if rule_owasp:
        owasp_categories.update(rule_owasp)

    if owasp_categories:
        compliance["owaspTop10_2021"] = sorted(list(owasp_categories))

    # CWE Top 25 2024
    if cwes:
        cwe_top25 = map_cwe_to_top25_2024(cwes)
        if cwe_top25:
            compliance["cweTop25_2024"] = cwe_top25

    # CIS Controls v8.1
    cis_controls = map_to_cis_controls_v8_1(tool_name, tags)
    if cis_controls:
        compliance["cisControlsV8_1"] = cis_controls

    # NIST CSF 2.0
    nist_csf = map_to_nist_csf_2_0(tool_name, tags, cwes)
    if nist_csf:
        compliance["nistCsf2_0"] = nist_csf

    # PCI DSS 4.0
    pci_dss = map_to_pci_dss_4_0(tool_name, tags, cwes)
    if pci_dss:
        compliance["pciDss4_0"] = pci_dss

    # MITRE ATT&CK
    mitre_attack = map_to_mitre_attack(tool_name, tags, cwes, rule_id)
    if mitre_attack:
        compliance["mitreAttack"] = mitre_attack

    # Update finding with compliance metadata
    if compliance:
        finding["compliance"] = compliance
        # Update schema version to 1.2.0
        finding["schemaVersion"] = "1.2.0"

    return finding


def enrich_findings_with_compliance(
    findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Enrich a list of findings with compliance framework mappings.

    Args:
        findings: List of CommonFinding dictionaries

    Returns:
        List of enriched findings with "compliance" field populated
    """
    return [enrich_finding_with_compliance(f) for f in findings]
