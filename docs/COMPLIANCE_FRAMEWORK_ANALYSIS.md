# Security Compliance Framework Analysis for JMo Security Audit Tool Suite

**Research Date:** 2025-10-16
**Framework Versions:** Current as of 2024-2025
**Purpose:** Identify optimal compliance frameworks for security scanning tool risk metadata

## Executive Summary

This analysis evaluates 12+ major security compliance frameworks to determine which should be implemented in the JMo Security Audit Tool Suite for risk metadata mapping. Based on comprehensive research, the **TOP 5 RECOMMENDED FRAMEWORKS** are:

1. **OWASP Top 10 2021** (with CWE Top 25 mapping)
2. **CIS Controls v8.1**
3. **NIST Cybersecurity Framework 2.0**
4. **PCI DSS 4.0**
5. **MITRE ATT&CK**

These frameworks provide maximum coverage with minimal redundancy, strong industry recognition, and practical mappings for SAST/secrets/SCA/IaC/container scanning findings.

---

## 1. Framework Analysis by Category

### 1.1 Application Security Frameworks (OWASP)

#### OWASP Top 10 2021 ⭐ **HIGHEST PRIORITY**

**Current Version:** 2021 edition (2024 update in progress, accepting contributions until July 2025)

**Coverage:**

- **A01:2021 - Broken Access Control**
- **A02:2021 - Cryptographic Failures** (includes hardcoded secrets, encryption issues)
- **A03:2021 - Injection** (33 CWEs mapped, SQL injection, command injection, etc.)
- **A04:2021 - Insecure Design**
- **A05:2021 - Security Misconfiguration** (IaC, container misconfigurations)
- **A06:2021 - Vulnerable and Outdated Components** (SCA/dependency scanning)
- **A07:2021 - Identification and Authentication Failures**
- **A08:2021 - Software and Data Integrity Failures** (supply chain, CI/CD security)
- **A09:2021 - Security Logging and Monitoring Failures**
- **A10:2021 - Server-Side Request Forgery (SSRF)**

**Mapping to JMo Tool Capabilities:**

| JMo Scanner | OWASP Top 10 Categories | Coverage |
|-------------|------------------------|----------|
| Trufflehog | A02 (Cryptographic Failures), A08 (Integrity) | Direct |
| Semgrep | A01, A03, A07, A09, A10 | High |
| Trivy | A02, A05, A06 | High |
| Checkov | A05 (Security Misconfiguration) | Direct |
| Bandit | A03, A02, A08 | Medium |
| Syft + Trivy | A06 (Vulnerable Components) | Direct |
| ZAP | A01, A03, A07, A10 | Direct |

**Industry Recognition:**

- Universal adoption across all industries
- Required knowledge for developers worldwide
- Maps to 100+ CWEs via official MITRE mappings
- Supported by all major SAST/DAST vendors

**Compliance Requirements:**

- Not legally mandated but industry best practice
- Often required in RFPs and security assessments
- Referenced in SOC 2, ISO 27001, PCI DSS guidance

**Practical Implementation:**

```yaml
# CommonFinding risk metadata example
compliance:
  owasp_top_10_2021:
    - id: "A02"
      category: "Cryptographic Failures"
      cwe_mappings: ["CWE-259", "CWE-798", "CWE-327"]
```

**Redundancy Analysis:**

- **Unique value:** Application-specific vulnerabilities
- **Overlaps with:** CWE Top 25 (addressed by using CWE mappings), ISO 27001 A.8.28/A.8.29
- **Recommendation:** Use as primary app-sec framework; CWE provides technical detail

#### OWASP ASVS 4.0 (Application Security Verification Standard) ⚠️ **SECONDARY PRIORITY**

**Current Version:** 4.0.3 (2021); Version 5.0 released at Global AppSec EU 2025

**Coverage:**

- 3-tiered verification levels (L1: Basic, L2: Standard, L3: Advanced)
- 14 security requirement categories
- 286 total security requirements in v4.0.3
- Covers V1 (Architecture), V2 (Authentication), V3 (Session), V4 (Access Control), V5 (Validation), etc.

**Mapping to JMo Tool Capabilities:**

- SAST tools can verify ~50% of ASVS requirements (human review needed for remainder)
- Requirements explicitly mention SAST/DAST in verification guidance
- Complements OWASP Top 10 with prescriptive requirements

**Industry Recognition:**

- Adopted by organizations requiring rigorous app-sec verification
- Used in procurement/vendor assessments
- Recognized by ISO 27034 (App Security)

**Compliance Requirements:**

- Not legally mandated
- Often required for high-security applications (financial, healthcare, government)
- Referenced in contracts for Level 2/3 assurance

**Practical Implementation:**

- **More suitable for manual security reviews than automated scanning**
- Could map specific SAST rules to ASVS requirements
- Better suited for security assessment reports than individual findings

**Redundancy Analysis:**

- **Unique value:** Prescriptive verification requirements, 3-tier maturity model
- **Overlaps with:** OWASP Top 10 (covers same vulnerabilities), NIST SP 800-53 SA-11
- **Recommendation:** **DEFER** - Focus on Top 10 for tool findings; ASVS better for program-level assessment

#### OWASP SAMM (Software Assurance Maturity Model) ❌ **NOT RECOMMENDED FOR FINDING METADATA**

**Current Version:** 2.0 (updated from 1.0 in 2019)

**Coverage:**

- 12 security practices grouped into 5 business functions
- Each practice has 2 streams with 3 maturity levels
- Covers entire SDLC (design, implementation, verification, deployment, operations)

**Mapping to JMo Tool Capabilities:**

- Framework is about **processes**, not individual findings
- SAST/SCA/secrets scanning are tools used to **implement** SAMM practices
- Example: Implementation → Build Security → Maturity Level 2 requires SAST/SCA integration

**Practical Implementation:**

- **Organizational maturity framework, not a finding classification system**
- JMo tool could support SAMM adoption (e.g., "enables SAMM Implementation.Build.2")
- Not suitable for per-finding risk metadata

**Redundancy Analysis:**

- **Unique value:** Software security program maturity assessment
- **Overlaps with:** None (different purpose - processes vs. findings)
- **Recommendation:** **NOT APPLICABLE** - Use for documentation/marketing ("JMo supports SAMM practices"), not finding metadata

---

### 1.2 Infrastructure/Controls Frameworks

#### CIS Controls v8.1 (2024) ⭐ **HIGH PRIORITY**

**Current Version:** v8.1 (June 2024)

**Coverage:**

- 18 critical security controls organized by Implementation Groups (IG1/IG2/IG3)
- **Control 16: Application Software Security** (directly applicable)
  - 16.1: Secure software development lifecycle
  - 16.2: SAST scans of applications
  - 16.3: DAST scans of code and libraries
  - 16.4: Code reviews
  - 16.5: Vulnerability remediation
- **Control 7: Continuous Vulnerability Management**
  - 7.1: Vulnerability scanning
  - 7.2: Remediation tracking
  - 7.3: Automated patching

**v8.1 Updates (2024):**

- Added "Governance" as a security function
- Enhanced glossary definitions (sensitive data, plans, policies)
- New "Documentation" asset type
- Improved Implementation Group mappings

**Mapping to JMo Tool Capabilities:**

| JMo Scanner | CIS Controls | Safeguards |
|-------------|--------------|------------|
| Trufflehog | 16.1 (SDLC), 3.11 (Data Protection) | IG1, IG2 |
| Semgrep | 16.2 (SAST), 16.4 (Code Review) | IG2, IG3 |
| Trivy | 7.1 (Vuln Mgmt), 16.3 (DAST) | IG1, IG2 |
| Checkov | 4.1 (Secure Config) | IG1, IG2 |
| Syft | 2.1 (Software Inventory), 7.1 (Vuln) | IG1 |
| Bandit | 16.2 (SAST) | IG2 |
| Hadolint | 4.1 (Secure Config) | IG1 |
| ZAP | 16.3 (DAST), 18.5 (Pen Testing) | IG2, IG3 |

**Industry Recognition:**

- Widely adopted across industries (finance, healthcare, government, critical infrastructure)
- Developed by consensus of global cybersecurity experts
- Cross-compatible with PCI DSS, GDPR, HIPAA, ISO 27001
- Following CIS Controls → satisfies most NIST CSF requirements

**Compliance Requirements:**

- Not legally mandated but strongly recommended
- Often required by cyber insurance providers
- CISA endorses CIS Controls for critical infrastructure

**Practical Implementation:**

```yaml
# CommonFinding risk metadata example
compliance:
  cis_controls_v8_1:
    - control: "16.2"
      safeguard: "16.2.1"
      title: "SAST Application Security Testing"
      implementation_group: "IG2"
```

**Redundancy Analysis:**

- **Unique value:** Prioritized, actionable controls backed by real-world attack data
- **Overlaps with:** NIST CSF (CIS is more tactical), ISO 27001 (CIS more specific)
- **Recommendation:** **INCLUDE** - Strong industry adoption, clear SAST/SCA/IaC mappings

#### NIST Cybersecurity Framework 2.0 (2024) ⭐ **HIGH PRIORITY**

**Current Version:** 2.0 (released February 2024)

**Coverage:**

- **6 Core Functions:** Govern, Identify, Protect, Detect, Respond, Recover
- **New in v2.0:**
  - **Govern** function (cybersecurity governance, leadership accountability)
  - Enhanced secure software development guidance (DevSecOps principles)
  - Expanded focus on secure coding practices and application security testing
  - Software component inventory management (open-source/third-party libraries)
- **Cross-references 50+ frameworks** including NIST SP 800-53, CIS Controls, ISO 27001

**Mapping to JMo Tool Capabilities:**

| JMo Scanner | NIST CSF 2.0 Categories | Functions |
|-------------|------------------------|-----------|
| Trufflehog | PR.DS (Data Security), PR.MA (Maintenance) | Protect |
| Semgrep | PR.IP (Identity & Privilege), DE.CM (Monitoring) | Protect, Detect |
| Trivy | ID.RA (Risk Assessment), PR.IP | Identify, Protect |
| Checkov | PR.IP, PR.DS | Protect |
| Syft | ID.AM (Asset Management), ID.RA | Identify |
| Bandit | DE.CM (Code Monitoring) | Detect |
| Hadolint | PR.IP (Secure Config) | Protect |
| ZAP | DE.AE (Adverse Events), RS.AN (Analysis) | Detect, Respond |

**Industry Recognition:**

- **Most popular security framework for 2024** (cited in industry surveys)
- Voluntary framework for critical infrastructure (Presidential directives)
- Adopted globally (not just US federal)
- Maps to ISO 27001, CIS Controls, COBIT, ISA/IEC 62443

**Compliance Requirements:**

- Voluntary for most sectors; mandatory for some US federal contractors
- Required for Executive Order 13636 compliance
- Often required in RFPs for government/critical infrastructure

**Practical Implementation:**

```yaml
# CommonFinding risk metadata example
compliance:
  nist_csf_2_0:
    - function: "Protect"
      category: "PR.DS-1"
      subcategory: "Data-at-rest is protected"
      informative_references:
        - "NIST SP 800-53 Rev 5: SC-28"
        - "CIS Controls v8: 3.11"
```

**Redundancy Analysis:**

- **Unique value:** High-level organizational risk management, maps to 50+ frameworks
- **Overlaps with:** CIS Controls (CSF more strategic, CIS more tactical), ISO 27001
- **Recommendation:** **INCLUDE** - Industry leader, enables mapping to NIST SP 800-53 and other frameworks

#### NIST SP 800-53 Rev 5 ⚠️ **SECONDARY PRIORITY (Via CSF 2.0)**

**Current Version:** Revision 5 Update 1 (December 2020)

**Coverage:**

- **1,000+ security and privacy controls** organized into 20 families
- **Key families for security scanning:**
  - **SA: System and Services Acquisition**
    - SA-11: Developer Testing and Evaluation (SAST, DAST, manual code review)
    - SA-15: Development Process, Standards, and Tools
  - **RA: Risk Assessment**
  - **SI: System and Information Integrity**
  - **CM: Configuration Management**

**SA-11 Control Enhancements:**

- SA-11(1): Static code analysis
- SA-11(2): Dynamic code analysis
- SA-11(3): Independent verification
- SA-11(4): Manual code reviews
- SA-11(5): Penetration testing

**SA-15 Control Enhancements:**

- SA-15(4): Threat modeling and vulnerability analysis
- SA-15(7): Automated vulnerability analysis

**Mapping to JMo Tool Capabilities:**

| JMo Scanner | NIST SP 800-53 Controls |
|-------------|------------------------|
| Trufflehog | SA-11(1), SA-15(7), SC-28 (Cryptographic Protection) |
| Semgrep | SA-11(1), SA-11(4), SI-11 (Error Handling) |
| Trivy | SA-11(2), RA-5 (Vulnerability Monitoring), CM-7 (Least Functionality) |
| Checkov | CM-2 (Baseline Config), CM-6 (Config Settings) |
| Syft | SA-8 (Security Engineering), CM-8 (System Component Inventory) |
| Bandit | SA-11(1), SA-15(4) |
| Hadolint | CM-6, CM-7 |
| ZAP | SA-11(2), SA-11(5), CA-8 (Penetration Testing) |

**Industry Recognition:**

- **De facto standard for US federal systems** (FISMA, FedRAMP)
- Adopted by critical infrastructure sectors
- International adoption via ISO 27001 alignment

**Compliance Requirements:**

- **Mandatory for US federal agencies** (FISMA)
- **Mandatory for cloud service providers** (FedRAMP)
- Required for DoD contractors (CMMC references SP 800-171, which is derived from 800-53)
- Strongly recommended for critical infrastructure

**Practical Implementation:**

```yaml
# CommonFinding risk metadata example
compliance:
  nist_sp_800_53_rev5:
    - control: "SA-11(1)"
      family: "System and Services Acquisition"
      title: "Developer Testing and Evaluation | Static Code Analysis"
```

**Redundancy Analysis:**

- **Unique value:** Comprehensive control catalog, federal mandate
- **Overlaps with:** NIST CSF 2.0 (CSF references 800-53), ISO 27001, CIS Controls
- **Recommendation:** **DEFER** - Access via CSF 2.0 informative references; too granular for individual findings
  - **Exception:** Include for tools targeting FedRAMP/FISMA compliance (future enhancement)

---

### 1.3 Vulnerability/Weakness Classifications

#### CWE Top 25 Most Dangerous Software Weaknesses (2024) ⭐ **ESSENTIAL (with OWASP)**

**Current Version:** 2024 edition (published November 2024 by CISA/MITRE)

**Methodology:**

- Analyzed 31,770 CVE records published June 2023 - June 2024
- Scored by prevalence and exploitability from National Vulnerability Database
- Maintained by MITRE, endorsed by CISA

**Top 10 Weaknesses (2024):**

1. **CWE-79:** Cross-Site Scripting (XSS) [#1]
2. **CWE-787:** Out-of-Bounds Write [#2]
3. **CWE-89:** SQL Injection [#3]
4. **CWE-22:** Path Traversal [#4]
5. **CWE-352:** Cross-Site Request Forgery (CSRF) [#5]
6. **CWE-434:** Unrestricted Upload of File with Dangerous Type [#6]
7. **CWE-862:** Missing Authorization [#7]
8. **CWE-78:** OS Command Injection [#8]
9. **CWE-502:** Deserialization of Untrusted Data [#9]
10. **CWE-94:** Code Injection [#10] (jumped 12 positions from 2023!)

**Notable 2024 Changes:**

- **CWE-94 (Code Injection)** surged from #22 to #11 (supply chain attacks)
- **CWE-502 (Deserialization)** remains critical
- **CWE-79 (XSS)** and **CWE-787 (Out-of-Bounds Write)** maintain top positions

**Mapping to JMo Tool Capabilities:**

| JMo Scanner | CWE Top 25 Coverage (Examples) |
|-------------|-------------------------------|
| Trufflehog | CWE-798 (Hardcoded Credentials), CWE-259 (Hardcoded Password) |
| Semgrep | CWE-79, CWE-89, CWE-22, CWE-78, CWE-94, CWE-352, CWE-502 |
| Trivy | CWE-1104 (Third-Party Components), CWE-327 (Weak Crypto) |
| Checkov | CWE-732 (Incorrect Permissions), CWE-250 (Execution with Unnecessary Privileges) |
| Bandit | CWE-89, CWE-78, CWE-327, CWE-798 |
| ZAP | CWE-79, CWE-89, CWE-352, CWE-434, CWE-862 |

**Industry Recognition:**

- **CISA-endorsed** (official government guidance)
- Referenced in OWASP Top 10, SANS, ISO 27001
- Used by NVD for CVE classification
- Universal adoption by SAST/DAST vendors

**Compliance Requirements:**

- Not a compliance framework but a **vulnerability taxonomy**
- Required for mapping to OWASP, NIST, ISO frameworks
- SARIF 2.1.0 uses CWE IDs in `rule.id` field

**Practical Implementation:**

```yaml
# CommonFinding schema (already implemented in JMo)
{
  "ruleId": "CWE-89",  # SQL Injection
  "tags": ["security", "cwe-top-25-2024", "owasp-a03-injection"],
  "compliance": {
    "cwe_top_25_2024": {
      "rank": 3,
      "category": "Injection",
      "cvss_base_score": 9.8
    }
  }
}
```

**Redundancy Analysis:**

- **Unique value:** Technical vulnerability taxonomy, CVE mappings
- **Overlaps with:** OWASP Top 10 (OWASP maps to CWEs), SANS (same source)
- **Recommendation:** **INCLUDE** - Essential for OWASP Top 10 mappings, already used in SAST tools

#### MITRE ATT&CK ⚠️ **SPECIALIZED USE CASE**

**Current Version:** v16.1 (Enterprise, Mobile, ICS matrices updated 2024)

**Coverage:**

- **14 Tactics** (Initial Access, Execution, Persistence, Privilege Escalation, etc.)
- **200+ Techniques** across Enterprise matrix
- **Supply Chain Compromise:** Technique T1195
  - T1195.001: Compromise Software Dependencies and Development Tools
  - T1195.002: Compromise Software Supply Chain
  - T1195.003: Compromise Hardware Supply Chain

**2024 Updates:**

- Expanded cloud-specific strategies (AWS, Azure, GCP)
- Enhanced software supply chain attack techniques
- Multi-stage attack scenarios

**Mapping to JMo Tool Capabilities:**

| JMo Scanner | ATT&CK Techniques |
|-------------|-------------------|
| Trufflehog | T1552 (Unsecured Credentials), T1078 (Valid Accounts) |
| Semgrep | T1059 (Command Injection), T1190 (Exploit Public-Facing App) |
| Trivy | T1195.002 (Compromise Software Supply Chain) |
| Checkov | T1078 (Valid Accounts), T1548 (Abuse Elevation) |
| Syft | T1195.001 (Software Dependencies) |
| Falco | T1611 (Escape to Host), T1610 (Deploy Container) |
| ZAP | T1190 (Exploit Public-Facing App), T1190 (Injection) |

**Industry Recognition:**

- **De facto standard for threat modeling and detection engineering**
- Used by SOCs, red teams, threat intelligence teams
- Integrated into SIEM/EDR/XDR platforms
- Referenced in NIST CSF 2.0, CISA guidance

**Compliance Requirements:**

- Not a compliance framework but a **threat taxonomy**
- Referenced in SOC 2, ISO 27001, NIST frameworks
- Required for threat-informed defense strategies

**Practical Implementation:**

```yaml
# CommonFinding risk metadata example
risk:
  mitre_attack:
    - tactic: "Initial Access"
      technique: "T1190"
      name: "Exploit Public-Facing Application"
      detection: "Web application vulnerability scanner"
```

**Redundancy Analysis:**

- **Unique value:** Adversarial tactics/techniques taxonomy, threat modeling
- **Overlaps with:** None (different purpose - offensive vs. defensive)
- **Recommendation:** **INCLUDE** - Provides threat context for findings, industry-standard threat taxonomy
  - **Caveat:** Not all findings map cleanly (e.g., IaC misconfigs → potential attack paths, not direct techniques)

#### OSC&R (Open Software Supply Chain Attack Reference) ℹ️ **EMERGING FRAMEWORK (Monitor)**

**Current Version:** Initial release 2024 (led by OX Security)

**Purpose:** MITRE ATT&CK-like framework specifically for **software supply chain attacks**

**Coverage:**

- Attacker behaviors and techniques targeting software supply chains
- CI/CD pipeline attacks
- Dependency confusion
- Code injection via compromised components

**Mapping to JMo Tool Capabilities:**

- Potential future mapping for Trufflehog, Trivy, Syft (supply chain focus)
- Complements MITRE ATT&CK T1195 techniques

**Recommendation:** **MONITOR** - Emerging framework, not widely adopted yet. Consider for v0.6.0+ if adoption grows.

---

### 1.4 Payment Card Industry / Financial

#### PCI DSS 4.0 ⭐ **HIGH PRIORITY (Financial Sector)**

**Current Version:** 4.0 (March 2022), latest requirements effective March 2025

**Coverage:**

- **12 Core Requirements** organized into 6 control objectives
- **Requirement 6: Develop and Maintain Secure Systems and Software**
  - 6.2.2: Developer training on secure coding
  - 6.2.3: Code review (manual + automated)
  - 6.2.4: Addressing common coding vulnerabilities
  - 6.3.1: Vulnerability identification and risk ranking
- **Requirement 11: Test Security of Systems and Networks Regularly**
  - 11.3.1.2: Authenticated vulnerability scanning (mandatory March 2025)
  - 11.3.2: External vulnerability scans (ASV quarterly)

**New in PCI DSS 4.0:**

- **Authenticated scanning** (credentialed scans) now mandatory (Req 11.3.1.2)
- Enhanced secure coding requirements (Req 6.2.x)
- All vulnerabilities must be fixed (not just CVSS 4.0+)
- API security requirements (Req 6.4.3)

**Mapping to JMo Tool Capabilities:**

| JMo Scanner | PCI DSS 4.0 Requirements |
|-------------|-------------------------|
| Trufflehog | Req 6.2.4 (Coding Vulnerabilities), Req 8 (Authentication) |
| Semgrep | Req 6.2.3 (Code Review), Req 6.2.4 |
| Trivy | Req 6.3.1 (Vulnerability Management), Req 11.3.1.2 (Scanning) |
| Checkov | Req 1 (Network Security), Req 2 (Secure Configurations) |
| Syft | Req 6.3.1 (Component Inventory) |
| Bandit | Req 6.2.4 (Python-specific vulnerabilities) |
| ZAP | Req 11.3.2 (External Scans), Req 6.4.3 (API Security) |

**Industry Recognition:**

- **Mandatory for all organizations handling payment card data** (Visa, Mastercard, etc.)
- Enforced by payment brands with penalties for non-compliance
- QSAs (Qualified Security Assessors) perform audits
- ASVs (Approved Scanning Vendors) required for external scans

**Compliance Requirements:**

- **Legally mandated** for merchants, service providers processing credit cards
- **Fines up to $500,000 per incident** for breaches
- Monthly/quarterly scanning requirements
- Annual on-site assessments for Level 1 merchants

**Practical Implementation:**

```yaml
# CommonFinding risk metadata example
compliance:
  pci_dss_4_0:
    - requirement: "6.2.4"
      objective: "Software and applications are free of coding vulnerabilities"
      testing_procedure: "6.2.4.a Examine documented procedures to verify..."
    - requirement: "6.3.1"
      cvss_threshold: "All vulnerabilities" # v4.0 change
```

**Redundancy Analysis:**

- **Unique value:** Payment card industry mandate, specific quarterly scanning requirements
- **Overlaps with:** ISO 27001 (A.8.28), NIST SP 800-53 (SA-11), CIS Controls (7.1, 16.2)
- **Recommendation:** **INCLUDE** - Mandatory for large user base (e-commerce, fintech), clear scanning requirements

---

### 1.5 Service Organization Controls (SOC 2)

#### SOC 2 Type 2 ⚠️ **SECTOR-SPECIFIC (SaaS/Cloud)**

**Current Version:** Based on AICPA TSC 2017 (Trust Services Criteria)

**Coverage:**

- **5 Trust Service Principles:** Security, Availability, Processing Integrity, Confidentiality, Privacy
- **CC7.1 (Common Criteria):** Detect and respond to vulnerabilities
- No explicit SAST requirement, but **vulnerability scanning + penetration testing** strongly recommended

**Key Security Practices:**

- Dependency testing and/or SAST scanning prior to production deployment
- Quarterly external vulnerability scans
- Annual penetration testing
- Continuous vulnerability management

**Mapping to JMo Tool Capabilities:**

| JMo Scanner | SOC 2 Criteria |
|-------------|----------------|
| Trufflehog | CC6.1 (Logical Access), CC6.7 (Encryption Keys) |
| Semgrep | CC7.1 (Vulnerability Detection), CC8.1 (Change Management) |
| Trivy | CC7.1 (Vulnerability Scanning), CC7.2 (Security Monitoring) |
| Checkov | CC6.6 (Logical Access Control Design) |
| Syft + Trivy | CC7.1 (Component Vulnerabilities) |
| ZAP | CC7.1 (Runtime Vulnerabilities) |

**Industry Recognition:**

- **Standard for SaaS/cloud service providers**
- Required by enterprise customers in procurement
- Demonstrates operational security controls over 6-12 months (Type 2)

**Compliance Requirements:**

- **Not legally mandated** but required by enterprise contracts
- Alternative to ISO 27001 for US-based companies
- Big 4 accounting firms perform audits

**Practical Implementation:**

```yaml
# CommonFinding risk metadata example
compliance:
  soc_2:
    - criterion: "CC7.1"
      principle: "Security"
      description: "Identifies and responds to risks associated with vulnerabilities"
```

**Redundancy Analysis:**

- **Unique value:** SaaS/cloud service provider assurance, enterprise procurement
- **Overlaps with:** ISO 27001 (similar controls), NIST CSF (maps to CSF categories)
- **Recommendation:** **DEFER** - Not a technical framework; no prescriptive mappings
  - **Alternative:** Document that JMo supports SOC 2 CC7.1 compliance (marketing/sales material)

---

### 1.6 International Standards

#### ISO 27001:2022 ⚠️ **GLOBAL STANDARD (Certification)**

**Current Version:** ISO/IEC 27001:2022 (October 2022 update)

**Coverage:**

- **93 controls** (down from 114 in 2013 version) organized into 4 themes:
  - Organizational, People, Physical, Technological
- **Key SDLC Controls:**
  - **A.8.25:** Secure development lifecycle
  - **A.8.28:** Secure coding
  - **A.8.29:** Security testing in development and acceptance

**A.8.28 Secure Coding:**

- Secure coding principles applied to software development
- Prevent, detect, and remediate common coding vulnerabilities
- Use of SAST and SCA tools explicitly mentioned

**A.8.29 Security Testing:**

- Security testing integrated into SDLC
- Combines SAST, SCA, DAST, IAST
- Checks for CWE Top 25, OWASP Top 10 vulnerabilities

**Mapping to JMo Tool Capabilities:**

| JMo Scanner | ISO 27001:2022 Controls |
|-------------|------------------------|
| Trufflehog | A.8.28 (Secure Coding), A.5.15 (Access Control) |
| Semgrep | A.8.28, A.8.29 (Security Testing) |
| Trivy | A.8.29, A.5.23 (Cloud Service Security) |
| Checkov | A.8.9 (Configuration Management), A.8.28 |
| Syft | A.5.20 (Addressing Security in Supplier Agreements) |
| Bandit | A.8.28, A.8.29 |
| ZAP | A.8.29 (Dynamic Testing) |

**Industry Recognition:**

- **Global standard** (adopted in 120+ countries)
- Certification by accredited bodies (UKAS, ANAB, etc.)
- Required for international business (especially EU, UK, APAC)

**Compliance Requirements:**

- **Not legally mandated** (except GDPR Article 32 references ISO 27001)
- Often required in government/enterprise procurement (EU, UK)
- Alternative to SOC 2 for global companies

**Practical Implementation:**

```yaml
# CommonFinding risk metadata example
compliance:
  iso_27001_2022:
    - control: "A.8.28"
      theme: "Technological"
      title: "Secure coding"
      objective: "Prevent coding vulnerabilities"
```

**Redundancy Analysis:**

- **Unique value:** Global certification, EU/UK market access
- **Overlaps with:** NIST SP 800-53 (both reference each other), CIS Controls, SOC 2
- **Recommendation:** **DEFER** - Better suited for organizational certification than finding metadata
  - **Alternative:** Document that JMo supports ISO 27001 A.8.28/A.8.29 (marketing material)
  - **Future consideration:** If international customers request it, add as secondary mapping

---

### 1.7 Healthcare / Regulated Industries

#### HIPAA + HITRUST CSF ⚠️ **HEALTHCARE-SPECIFIC**

**HIPAA (Health Insurance Portability and Accountability Act):**

- **Not a technical framework** - US federal law for patient data protection
- Security Rule requires risk assessments, vulnerability scanning, penetration testing
- No prescriptive technical controls (unlike PCI DSS)

**HITRUST CSF (Common Security Framework):**

- **v11** (latest version)
- **49 control objectives, 156 control specifications**
- Harmonizes HIPAA, ISO 27001, NIST, PCI DSS, GDPR
- Certification by HITRUST assessors

**Mapping to JMo Tool Capabilities:**

- HITRUST incorporates NIST SP 800-53, ISO 27001, PCI DSS controls
- Vulnerability scanning and penetration testing reports required for certification
- JMo findings map via NIST/ISO/PCI DSS controls

**Industry Recognition:**

- **Healthcare industry standard** (hospitals, health tech, insurers)
- Required by healthcare enterprise customers
- Alternative to SOC 2 for healthcare SaaS

**Compliance Requirements:**

- **HIPAA legally mandated** for covered entities/business associates
- **HITRUST voluntary** but required by contracts
- Demonstrates HIPAA compliance via certification

**Redundancy Analysis:**

- **Unique value:** Healthcare sector requirement
- **Overlaps with:** NIST SP 800-53, ISO 27001, PCI DSS (HITRUST harmonizes all)
- **Recommendation:** **DEFER** - Access via NIST/ISO/PCI DSS mappings
  - **Future consideration:** If healthcare customers request, add HITRUST control IDs as secondary mapping

#### FedRAMP / FISMA ⚠️ **US FEDERAL GOVERNMENT**

**FISMA (Federal Information Security Modernization Act):**

- **US federal law** requiring agencies to implement NIST SP 800-53
- Continuous monitoring, vulnerability scanning, annual assessments

**FedRAMP (Federal Risk and Authorization Management Program):**

- **Cloud service authorization program** for US government
- Built on NIST SP 800-53 Rev 5 with additional cloud-specific controls
- **3PAO (Third-Party Assessment Organization)** required for certification

**Mapping to JMo Tool Capabilities:**

- **Same as NIST SP 800-53 Rev 5** (SA-11, RA-5, CM-6, etc.)
- Continuous monitoring requirements (quarterly scans minimum)

**Compliance Requirements:**

- **FISMA: Mandatory for US federal agencies**
- **FedRAMP: Mandatory for cloud providers serving federal customers**
- Severe penalties for non-compliance

**Redundancy Analysis:**

- **Unique value:** US federal market access
- **Overlaps with:** NIST SP 800-53 Rev 5 (FedRAMP = 800-53 + cloud controls)
- **Recommendation:** **DEFER** - Access via NIST CSF 2.0 → SP 800-53 mappings
  - **Future consideration:** If targeting federal market, add FedRAMP control IDs

---

## 2. Framework Redundancy Analysis

### High Overlap Frameworks (Choose One)

| Primary Framework | Redundant With | Recommendation |
|------------------|----------------|----------------|
| **OWASP Top 10 2021** | OWASP ASVS, SANS Top 25 | **Use OWASP Top 10** - Industry standard, maps to CWE |
| **CIS Controls v8.1** | NIST CSF 2.0 (tactical level), ISO 27001 | **Use CIS Controls** - More actionable for SAST/SCA tools |
| **NIST CSF 2.0** | NIST SP 800-53, ISO 27001, CIS Controls | **Use CSF 2.0** - Maps to all others, industry leader |
| **CWE Top 25** | SANS Top 25 (same source) | **Use CWE Top 25** - CISA-endorsed, NVD standard |
| **PCI DSS 4.0** | ISO 27001, NIST SP 800-53 | **Use PCI DSS** - Mandatory for payment industry |

### Complementary Frameworks (Use Together)

| Framework Pair | Rationale |
|----------------|-----------|
| **OWASP Top 10 + CWE Top 25** | OWASP provides categories; CWE provides technical IDs |
| **NIST CSF 2.0 + CIS Controls** | CSF for strategic; CIS for tactical implementation |
| **OWASP Top 10 + MITRE ATT&CK** | OWASP for vulnerabilities; ATT&CK for threat context |

---

## 3. Top 5 Recommended Frameworks for JMo Tool Suite

### Priority 1: OWASP Top 10 2021 (with CWE Mappings)

**Rationale:**

- Universal application security standard
- Direct mapping to SAST/secrets/SCA/DAST findings
- Industry recognition across all sectors
- Official CWE mappings (100+ CWEs) via MITRE
- All major security tools report OWASP categories

**Implementation:**

```yaml
# CommonFinding schema extension
compliance:
  owasp_top_10_2021:
    - id: "A02"
      category: "Cryptographic Failures"
      cwe_mappings: ["CWE-259", "CWE-798", "CWE-327", "CWE-321"]
  cwe_top_25_2024:
    - id: "CWE-798"
      rank: 16
      name: "Use of Hard-coded Credentials"
```

**Coverage:** Trufflehog, Semgrep, Trivy, Bandit, ZAP

---

### Priority 2: CIS Controls v8.1

**Rationale:**

- **Control 16 (Application Software Security)** directly maps to SAST/SCA
- **Control 7 (Continuous Vulnerability Management)** maps to SCA/container scanning
- Prioritized by Implementation Groups (IG1/IG2/IG3) - helps users understand maturity
- Cross-compatible with PCI DSS, HIPAA, ISO 27001, GDPR
- Backed by real-world attack data

**Implementation:**

```yaml
# CommonFinding schema extension
compliance:
  cis_controls_v8_1:
    - control: "16.2"
      safeguard: "16.2.1"
      title: "Establish and Maintain a Secure Application Development Process"
      implementation_group: "IG2"
      description: "SAST scanning of application source code"
```

**Coverage:** All JMo scanners map to CIS Controls 7, 16, or 4

---

### Priority 3: NIST Cybersecurity Framework 2.0

**Rationale:**

- **Most popular framework in 2024** (industry surveys)
- Cross-references 50+ frameworks (NIST SP 800-53, CIS, ISO 27001, MITRE ATT&CK)
- Required for US federal contractors and critical infrastructure
- **New Govern function** emphasizes secure SDLC
- Enables mapping to detailed NIST SP 800-53 controls via informative references

**Implementation:**

```yaml
# CommonFinding schema extension
compliance:
  nist_csf_2_0:
    - function: "Protect"
      category: "PR.DS-1"
      subcategory: "Data-at-rest is protected"
      informative_references:
        - framework: "NIST SP 800-53 Rev 5"
          control: "SC-28"
        - framework: "CIS Controls v8"
          control: "3.11"
        - framework: "ISO 27001:2022"
          control: "A.8.24"
```

**Coverage:** Strategic framework - all JMo findings map to CSF categories

---

### Priority 4: PCI DSS 4.0

**Rationale:**

- **Mandatory for payment card industry** (e-commerce, fintech, retail)
- Explicit scanning requirements (quarterly authenticated scans)
- **Requirement 6.2.4** - coding vulnerabilities
- **Requirement 11.3** - vulnerability scanning
- Large user base (millions of merchants worldwide)
- Severe penalties for non-compliance (up to $500K per breach)

**Implementation:**

```yaml
# CommonFinding schema extension
compliance:
  pci_dss_4_0:
    - requirement: "6.2.4"
      objective: "Address common coding vulnerabilities in software-development processes"
      testing_procedure: "6.2.4.a Examine documented procedures and interview personnel"
    - requirement: "11.3.1.2"
      objective: "Internal vulnerability scans are performed via authenticated scanning"
      effective_date: "2025-03-31"  # Mandatory after this date
```

**Coverage:** Trufflehog, Semgrep, Trivy, Checkov (Req 6, 11)

---

### Priority 5: MITRE ATT&CK

**Rationale:**

- **De facto threat modeling standard** (SOCs, red teams, threat intelligence)
- Provides **adversarial context** for findings (how would an attacker exploit this?)
- **Supply chain techniques** (T1195) map to Trivy/Syft/Semgrep findings
- Integrated into SIEM/EDR/XDR platforms
- Helps prioritize findings based on threat landscape
- Referenced in NIST CSF 2.0, CISA guidance

**Implementation:**

```yaml
# CommonFinding schema extension
risk:
  mitre_attack:
    - tactic: "Initial Access"
      technique: "T1190"
      name: "Exploit Public-Facing Application"
      subtechnique: null
      detection: "Web application vulnerability scanner detected exploitable flaw"
    - tactic: "Credential Access"
      technique: "T1552"
      name: "Unsecured Credentials"
      subtechnique: "T1552.001"  # Credentials In Files
```

**Coverage:** Trufflehog (T1552), Semgrep (T1059, T1190), Trivy (T1195), ZAP (T1190)

---

## 4. Deferred Frameworks (Not Recommended for v0.5.0)

### Deferred with Rationale:

| Framework | Reason for Deferral |
|-----------|---------------------|
| **OWASP ASVS 4.0** | Better for manual assessment than automated findings; redundant with OWASP Top 10 |
| **OWASP SAMM 2.0** | Process maturity framework, not finding metadata; use for documentation/marketing |
| **NIST SP 800-53 Rev 5** | Access via CSF 2.0 informative references; too granular (1000+ controls) |
| **ISO 27001:2022** | Certification framework; redundant with NIST/CIS; better for organizational docs |
| **SOC 2 Type 2** | No prescriptive mappings; document support in marketing materials instead |
| **HITRUST CSF** | Healthcare-specific; redundant with NIST/ISO/PCI DSS; add if customers request |
| **FedRAMP/FISMA** | US federal-specific; access via NIST SP 800-53; add if targeting federal market |
| **OSC&R** | Emerging framework; monitor for future adoption; consider for v0.6.0+ |

---

## 5. Implementation Roadmap

### Phase 1: v0.5.0 - Core Framework Support (Current)

**Implement TOP 3 frameworks:**

1. ✅ **OWASP Top 10 2021 + CWE Top 25 2024**
   - Add `compliance.owasp_top_10_2021` field to CommonFinding schema
   - Add `compliance.cwe_top_25_2024` field with rank/category
   - Map existing tool ruleIds to OWASP categories (see Appendix A)
   - Update SARIF reporter to include OWASP/CWE tags

2. ✅ **CIS Controls v8.1**
   - Add `compliance.cis_controls_v8_1` field
   - Map findings to Control 16 (App Security), Control 7 (Vuln Mgmt), Control 4 (Config)
   - Include Implementation Group (IG1/IG2/IG3) for prioritization
   - Update dashboard.html to filter by CIS Implementation Group

3. ✅ **NIST CSF 2.0**
   - Add `compliance.nist_csf_2_0` field with function/category/subcategory
   - Include informative references to NIST SP 800-53, CIS, ISO 27001
   - Map all findings to CSF 2.0 categories (Identify, Protect, Detect)
   - Generate compliance summary report (counts by CSF function)

**Deliverables:**

- Updated `docs/schemas/common_finding.v1.json` with compliance fields
- Adapter updates to populate compliance metadata from tool outputs
- Dashboard enhancements (filter by framework, compliance summary widgets)
- Documentation: `docs/COMPLIANCE_MAPPING.md` (framework descriptions, mapping tables)

### Phase 2: v0.6.0 - Compliance-Driven Features

**Add frameworks 4-5:**

4. **PCI DSS 4.0**
   - Add `compliance.pci_dss_4_0` field
   - Implement PCI DSS compliance report (`PCI_DSS_COMPLIANCE.md`)
   - Add `--fail-on-pci` flag (fail if Req 6.2.4 / Req 11.3 violations detected)
   - Generate ASV-style scan report format (for external scans)

5. **MITRE ATT&CK**
   - Add `risk.mitre_attack` field (tactic/technique/subtechnique)
   - Map findings to ATT&CK techniques (T1190, T1552, T1195, etc.)
   - Add ATT&CK Navigator JSON export (visualize coverage in ATT&CK matrix)
   - Dashboard: ATT&CK technique heatmap

**New Features:**

- **Compliance profiles:** `--compliance-profile pci-dss` (filter tools/rules to PCI DSS scope)
- **Compliance reports:** `jmo report --compliance-format pci-dss` (generate PCI DSS-specific report)
- **Threshold gating:** `--fail-on-compliance "pci-dss:req-6.2.4"` (CI/CD gates by compliance requirement)

### Phase 3: v0.7.0+ - Enterprise/Government Frameworks (On-Demand)

**Add if customer demand exists:**

6. **NIST SP 800-53 Rev 5** (FedRAMP/FISMA customers)
7. **ISO 27001:2022** (International customers, EU/UK markets)
8. **HITRUST CSF** (Healthcare customers)
9. **SOC 2** (SaaS customers - document support, not metadata)

**Implementation approach:**

- Survey customers (GitHub Discussions, issues, enterprise feedback)
- Prioritize by number of requests + market size
- Implement as optional compliance plugins (reduce bloat for users who don't need them)

---

## 6. Framework Mapping Tables

### OWASP Top 10 2021 → JMo Tool Coverage

| OWASP Category | CWE Mappings (Top 5) | JMo Scanners | Coverage Level |
|----------------|---------------------|--------------|----------------|
| **A01: Broken Access Control** | CWE-862, CWE-863, CWE-285, CWE-639, CWE-732 | Semgrep, ZAP, Checkov | Medium |
| **A02: Cryptographic Failures** | CWE-259, CWE-798, CWE-327, CWE-321, CWE-326 | Trufflehog, Semgrep, Trivy, Bandit | **High** |
| **A03: Injection** | CWE-79, CWE-89, CWE-78, CWE-94, CWE-352 | Semgrep, Bandit, ZAP | **High** |
| **A04: Insecure Design** | CWE-209, CWE-256, CWE-501, CWE-522, CWE-611 | Semgrep, Checkov | Low |
| **A05: Security Misconfiguration** | CWE-16, CWE-2, CWE-749, CWE-538, CWE-731 | Checkov, Trivy, Hadolint | **High** |
| **A06: Vulnerable Components** | CWE-1104, CWE-937, CWE-1035 | Syft, Trivy | **High** |
| **A07: Auth Failures** | CWE-287, CWE-306, CWE-798, CWE-640, CWE-916 | Semgrep, Trufflehog, ZAP | Medium |
| **A08: Integrity Failures** | CWE-829, CWE-494, CWE-502, CWE-345, CWE-353 | Trivy, Semgrep | Medium |
| **A09: Logging Failures** | CWE-117, CWE-223, CWE-532, CWE-778 | Semgrep, Bandit | Low |
| **A10: SSRF** | CWE-918 | Semgrep, ZAP | Medium |

### CIS Controls v8.1 → JMo Tool Coverage

| CIS Control | Safeguards | JMo Scanners | Implementation Group |
|-------------|-----------|--------------|---------------------|
| **2.1: Asset Inventory** | Software inventory (SBOM) | Syft, Trivy | IG1 |
| **3.11: Data Protection** | Encryption, secrets management | Trufflehog | IG2 |
| **4.1: Secure Configuration** | Baseline configs, IaC | Checkov, Hadolint, Trivy | IG1 |
| **7.1: Vulnerability Management** | Continuous scanning, remediation | Trivy, Semgrep | IG1 |
| **16.1: Secure SDLC** | Development processes | All scanners | IG2 |
| **16.2: SAST** | Static code analysis | Semgrep, Bandit | IG2 |
| **16.3: DAST** | Dynamic testing | ZAP, Trivy | IG2 |
| **16.4: Code Review** | Peer review, automated review | Semgrep | IG2 |
| **16.5: Vulnerability Remediation** | Fix tracking | Trivy, Semgrep | IG2 |
| **18.5: Penetration Testing** | Security assessment | ZAP | IG3 |

### NIST CSF 2.0 → JMo Tool Coverage

| CSF Function | Categories | JMo Scanners | Informative Refs |
|--------------|-----------|--------------|------------------|
| **Govern (GV)** | GV.SC-3 (Software lifecycle) | All scanners | NIST SP 800-53: SA-8, SA-15 |
| **Identify (ID)** | ID.AM-2 (Software inventory), ID.RA-1 (Vulnerability ID) | Syft, Trivy | NIST SP 800-53: CM-8, RA-5 |
| **Protect (PR)** | PR.DS-1 (Data protection), PR.IP-12 (Vuln response) | Trufflehog, Trivy | NIST SP 800-53: SC-28, SI-2 |
| **Detect (DE)** | DE.CM-8 (Vuln scans), DE.AE-1 (Adverse events) | Semgrep, ZAP, Trivy | NIST SP 800-53: RA-5, SI-4 |

### PCI DSS 4.0 → JMo Tool Coverage

| Requirement | Testing Procedure | JMo Scanners | Mandatory Date |
|-------------|------------------|--------------|----------------|
| **6.2.2: Developer Training** | Interview developers, review training | N/A (documentation) | Current |
| **6.2.3: Code Review** | Examine code review process | Semgrep (automated review) | Current |
| **6.2.4: Coding Vulnerabilities** | Verify OWASP Top 10, CWE mitigation | Semgrep, Bandit, Trufflehog | Current |
| **6.3.1: Vulnerability Management** | Review vuln scanning process, rankings | Trivy, Semgrep | Current |
| **11.3.1.2: Authenticated Scanning** | Verify credentialed scans quarterly | Trivy (container), Semgrep (code) | 2025-03-31 |
| **11.3.2: External Scans** | ASV scans quarterly, CVSS 4.0+ remediation | ZAP, Trivy | Current |

### MITRE ATT&CK → JMo Tool Coverage

| Tactic | Technique | JMo Scanners | Detection Method |
|--------|-----------|--------------|------------------|
| **Initial Access** | T1190 (Exploit Public App) | ZAP, Semgrep | Web vuln scanning |
| **Execution** | T1059 (Command Injection) | Semgrep, Bandit | SAST code analysis |
| **Persistence** | T1136 (Create Account) | Checkov (IaC misconfigs) | Config scanning |
| **Privilege Escalation** | T1548 (Abuse Elevation) | Checkov, Semgrep | Permission checks |
| **Credential Access** | T1552 (Unsecured Credentials) | Trufflehog, Semgrep | Secrets scanning |
| **Credential Access** | T1552.001 (Credentials in Files) | Trufflehog | Verified secrets |
| **Defense Evasion** | T1027 (Obfuscated Files) | Semgrep | Code pattern matching |
| **Initial Access** | T1195 (Supply Chain Compromise) | Trivy, Syft | Dependency scanning |
| **Initial Access** | T1195.001 (Software Dependencies) | Trivy, Syft | SCA, SBOM |
| **Initial Access** | T1195.002 (Software Supply Chain) | Trivy, Syft | Vuln in deps |

---

## 7. Practical Recommendations

### For JMo v0.5.0 Implementation:

1. **Update CommonFinding Schema (v1.1):**

   ```json
   {
     "schemaVersion": "1.1",
     "id": "fingerprint-id",
     "ruleId": "CWE-798",
     "severity": "HIGH",
     "compliance": {
       "owasp_top_10_2021": [
         {
           "id": "A02",
           "category": "Cryptographic Failures",
           "description": "Use of hard-coded credentials"
         }
       ],
       "cwe_top_25_2024": {
         "id": "CWE-798",
         "rank": 16,
         "name": "Use of Hard-coded Credentials",
         "cvss_base_score": 7.8
       },
       "cis_controls_v8_1": [
         {
           "control": "16.1",
           "safeguard": "16.1.1",
           "title": "Establish Secure SDLC",
           "implementation_group": "IG2"
         }
       ],
       "nist_csf_2_0": {
         "function": "Protect",
         "category": "PR.DS-1",
         "subcategory": "Data-at-rest is protected",
         "informative_references": [
           {"framework": "NIST SP 800-53 Rev 5", "control": "SC-28"},
           {"framework": "CIS Controls v8", "control": "3.11"}
         ]
       },
       "pci_dss_4_0": [
         {
           "requirement": "6.2.4",
           "objective": "Address coding vulnerabilities"
         }
       ]
     },
     "risk": {
       "mitre_attack": [
         {
           "tactic": "Credential Access",
           "technique": "T1552",
           "name": "Unsecured Credentials",
           "subtechnique": "T1552.001",
           "description": "Credentials In Files"
         }
       ]
     }
   }
   ```

2. **Adapter Updates:**

   - Modify `scripts/core/adapters/*_adapter.py` to populate `compliance` and `risk` fields
   - Create `scripts/core/compliance_mapper.py` utility:
     - `map_cwe_to_owasp(cwe_id) -> List[OWASPCategory]`
     - `map_rule_to_cis(tool, rule_id) -> List[CISControl]`
     - `map_vuln_to_attack(cwe_id, context) -> List[AttackTechnique]`

3. **Reporter Enhancements:**

   - **HTML Dashboard:** Add compliance filter dropdown (OWASP A01-A10, CIS IG1/IG2/IG3, CSF functions)
   - **SARIF Reporter:** Include compliance tags in `result.taxa` field
   - **New Reporter:** `compliance_reporter.py` (generates framework-specific reports)

4. **Configuration:**

   ```yaml
   # jmo.yml
   compliance:
     enabled: true
     frameworks:
       - owasp_top_10_2021
       - cwe_top_25_2024
       - cis_controls_v8_1
       - nist_csf_2_0
       - pci_dss_4_0  # optional, enable for payment industry
     output_formats:
       - json  # findings.json with compliance metadata
       - md    # COMPLIANCE_SUMMARY.md
       - html  # dashboard.html with compliance filters
   ```

5. **Documentation:**

   - Create `docs/COMPLIANCE_MAPPING.md`:
     - Framework descriptions
     - Mapping tables (OWASP → JMo, CIS → JMo, etc.)
     - Compliance report examples
     - FAQ: "Which framework should I use?"
   - Update `README.md`:
     - Add "Compliance Frameworks" section
     - Badge: "Supports OWASP Top 10, CIS Controls, NIST CSF, PCI DSS"
   - Update `QUICKSTART.md`:
     - Example: `jmo report --compliance-summary`

6. **Testing:**

   - Add `tests/compliance/test_compliance_mapper.py`
   - Add `tests/reporters/test_compliance_reporter.py`
   - Integration test: `tests/integration/test_compliance_report.py`

---

## 8. Industry-Specific Guidance

### Financial Services / E-commerce

**Required Frameworks:**

1. **PCI DSS 4.0** (mandatory)
2. **OWASP Top 10 2021** (industry best practice)
3. **CIS Controls v8.1** (cyber insurance requirement)

**Key Compliance Points:**

- Quarterly authenticated scans (PCI DSS 11.3.1.2)
- All vulnerabilities must be remediated (PCI DSS 6.3.1 - v4.0 change)
- SAST/SCA required in SDLC (PCI DSS 6.2.3, 6.2.4)

### Healthcare / Medical Devices

**Required Frameworks:**

1. **HIPAA Security Rule** (access via NIST SP 800-53)
2. **HITRUST CSF** (contract requirement)
3. **ISO 27001** (international markets)

**Key Compliance Points:**

- Risk assessments (HIPAA §164.308)
- Vulnerability scanning (HITRUST 01.m, 01.n)
- FDA premarket cybersecurity guidance (medical devices)

### SaaS / Cloud Services

**Required Frameworks:**

1. **SOC 2 Type 2** (enterprise procurement)
2. **ISO 27001** (global customers)
3. **NIST CSF 2.0** (industry best practice)

**Key Compliance Points:**

- Continuous vulnerability management (SOC 2 CC7.1)
- SAST/SCA in CI/CD (ISO 27001 A.8.29)
- Quarterly pen tests (SOC 2 best practice)

### Government / Critical Infrastructure

**Required Frameworks:**

1. **NIST SP 800-53 Rev 5** (FedRAMP, FISMA)
2. **NIST CSF 2.0** (voluntary framework)
3. **CIS Controls v8.1** (CISA recommended)

**Key Compliance Points:**

- Continuous monitoring (NIST SP 800-53 CA-7)
- Developer security testing (SA-11)
- Supply chain risk management (SR-3, SR-5)

---

## 9. Mapping Challenges and Solutions

### Challenge 1: Partial Coverage

**Problem:** Not all findings map cleanly to all frameworks

**Example:** Falco runtime detections (container escapes) don't map to OWASP Top 10

**Solution:**

- Mark coverage as "N/A" when no mapping exists
- Use MITRE ATT&CK for runtime detections (T1611: Escape to Host)
- Document coverage gaps in `docs/COMPLIANCE_MAPPING.md`

### Challenge 2: Many-to-Many Mappings

**Problem:** One CWE maps to multiple OWASP categories; one OWASP category maps to 33 CWEs

**Example:** CWE-798 (Hardcoded Credentials) maps to OWASP A02 (Cryptographic Failures) AND A07 (Auth Failures)

**Solution:**

- Include **all** applicable mappings in `compliance` array
- Rank by relevance (primary vs. secondary mappings)
- Dashboard: Allow filtering by ANY matching framework category

### Challenge 3: Framework Version Changes

**Problem:** OWASP Top 10 2024 will replace 2021; CIS Controls v9 will replace v8.1

**Solution:**

- Version all compliance fields: `owasp_top_10_2021`, `cis_controls_v8_1`
- Support multiple versions simultaneously (allow users to choose)
- Deprecation policy: Support N and N-1 versions; remove N-2 after 2 years
- Auto-migration scripts when new versions released

### Challenge 4: Framework Granularity Mismatch

**Problem:** NIST SP 800-53 has 1000+ controls; too granular for per-finding metadata

**Solution:**

- Use **informative references** approach (NIST CSF 2.0 model)
- Primary mapping: NIST CSF 2.0 categories
- Secondary mapping: Link to SP 800-53 via CSF informative references
- Generate compliance matrix separately (not embedded in each finding)

---

## 10. Glossary

| Term | Definition |
|------|------------|
| **ASVS** | Application Security Verification Standard (OWASP) |
| **ASV** | Approved Scanning Vendor (PCI DSS) |
| **ATT&CK** | Adversarial Tactics, Techniques, and Common Knowledge (MITRE) |
| **CIS** | Center for Internet Security |
| **CSF** | Cybersecurity Framework (NIST) |
| **CWE** | Common Weakness Enumeration |
| **DAST** | Dynamic Application Security Testing |
| **FedRAMP** | Federal Risk and Authorization Management Program |
| **FISMA** | Federal Information Security Modernization Act |
| **HITRUST** | Health Information Trust Alliance |
| **IaC** | Infrastructure as Code |
| **SAST** | Static Application Security Testing |
| **SCA** | Software Composition Analysis |
| **SARIF** | Static Analysis Results Interchange Format |
| **SBOM** | Software Bill of Materials |
| **SOC 2** | Service Organization Control 2 |

---

## 11. References

### Official Framework Sources

1. **OWASP Top 10 2021:** https://owasp.org/Top10/
2. **OWASP ASVS 4.0.3:** https://github.com/OWASP/ASVS
3. **OWASP SAMM 2.0:** https://owaspsamm.org/
4. **CWE Top 25 2024:** https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html
5. **CIS Controls v8.1:** https://www.cisecurity.org/controls/v8
6. **NIST CSF 2.0:** https://www.nist.gov/cyberframework
7. **NIST SP 800-53 Rev 5:** https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
8. **MITRE ATT&CK v16.1:** https://attack.mitre.org/
9. **PCI DSS 4.0:** https://www.pcisecuritystandards.org/document_library/
10. **ISO 27001:2022:** https://www.iso.org/standard/27001
11. **SARIF 2.1.0:** https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

### Mapping Resources

- **OpenCRE (Open Common Requirement Enumeration):** https://www.opencre.org/
- **CIS Controls → NIST CSF Mapping:** https://www.cisecurity.org/insights/white-papers/cis-controls-v8-mapping-to-nist-csf-2-0
- **OWASP Top 10 → CWE Mapping:** https://github.com/OWASP/Top10/blob/master/2021/Data/CWE-Guidance.md

---

## Appendix A: Tool-Specific Compliance Mappings

### Trufflehog → Compliance Frameworks

| Finding Type | OWASP 2021 | CWE Top 25 | CIS v8.1 | NIST CSF 2.0 | ATT&CK |
|--------------|------------|-----------|----------|--------------|--------|
| Hardcoded AWS Keys | A02 | CWE-798 (#16) | 3.11, 16.1 | PR.DS-1 | T1552.001 |
| GitHub Token | A02 | CWE-798 | 3.11, 16.1 | PR.DS-1 | T1552.001 |
| Private SSH Key | A02 | CWE-321 | 3.11 | PR.DS-1 | T1552.004 |
| Database Password | A02, A07 | CWE-798 | 3.11, 16.1 | PR.DS-1 | T1552.001 |

### Semgrep → Compliance Frameworks

| Rule Category | OWASP 2021 | CWE Top 25 | CIS v8.1 | NIST CSF 2.0 | ATT&CK |
|---------------|------------|-----------|----------|--------------|--------|
| SQL Injection | A03 | CWE-89 (#3) | 16.2 | DE.CM-8 | T1190 |
| Command Injection | A03 | CWE-78 (#8) | 16.2 | DE.CM-8 | T1059 |
| XSS | A03 | CWE-79 (#1) | 16.2 | DE.CM-8 | T1190 |
| Path Traversal | A01, A03 | CWE-22 (#4) | 16.2 | DE.CM-8 | T1083 |
| CSRF | A01 | CWE-352 (#5) | 16.2 | DE.CM-8 | T1190 |
| Deserialization | A08 | CWE-502 (#9) | 16.2 | DE.CM-8 | T1059 |

### Trivy → Compliance Frameworks

| Finding Type | OWASP 2021 | CWE Top 25 | CIS v8.1 | NIST CSF 2.0 | PCI DSS 4.0 | ATT&CK |
|--------------|------------|-----------|----------|--------------|-------------|--------|
| CVE in npm package | A06 | CWE-1104 | 7.1, 2.1 | ID.RA-1 | 6.3.1 | T1195.001 |
| Container misconfiguration | A05 | CWE-16 | 4.1 | PR.IP-1 | 2.2.1 | T1610 |
| Weak crypto algorithm | A02 | CWE-327 | 3.11 | PR.DS-1 | 6.2.4 | T1573.001 |
| Secret in image | A02 | CWE-798 | 3.11, 16.1 | PR.DS-1 | 6.2.4 | T1552.001 |

### Checkov → Compliance Frameworks

| Resource Type | OWASP 2021 | CWE | CIS v8.1 | NIST CSF 2.0 | PCI DSS 4.0 |
|---------------|------------|-----|----------|--------------|-------------|
| AWS S3 Public Bucket | A01, A05 | CWE-732 | 4.1, 3.11 | PR.DS-5 | 1.2.1 |
| Unencrypted RDS | A02 | CWE-311 | 3.11 | PR.DS-1 | 3.4.1 |
| IAM Overprivileged | A01 | CWE-250 | 6.1 | PR.AC-4 | 7.1.2 |
| No MFA on root | A07 | CWE-306 | 6.3 | PR.AC-7 | 8.3.1 |

---

## Appendix B: Sample Compliance Reports

### Example 1: OWASP Top 10 Summary

```markdown
# OWASP Top 10 2021 Compliance Report

**Scan Date:** 2025-10-16
**Repository:** jmo-security-repo
**Total Findings:** 42

## Findings by OWASP Category

| Category | Severity Distribution | Total | Status |
|----------|----------------------|-------|--------|
| **A02: Cryptographic Failures** | CRITICAL: 2, HIGH: 5, MEDIUM: 3 | 10 | ⚠️ Action Required |
| **A03: Injection** | HIGH: 3, MEDIUM: 4, LOW: 1 | 8 | ⚠️ Action Required |
| **A05: Security Misconfiguration** | HIGH: 2, MEDIUM: 6 | 8 | ⚠️ Action Required |
| **A06: Vulnerable Components** | CRITICAL: 1, HIGH: 4, MEDIUM: 8 | 13 | ⚠️ Action Required |
| **A01: Broken Access Control** | MEDIUM: 2, LOW: 1 | 3 | ℹ️ Review Recommended |

## Top CWE Weaknesses

1. **CWE-798:** Use of Hard-coded Credentials (8 findings) → Rank #16 in CWE Top 25 2024
2. **CWE-89:** SQL Injection (3 findings) → Rank #3 in CWE Top 25 2024
3. **CWE-1104:** Vulnerable Third-Party Component (13 findings)

## Recommendations

1. **Immediate Action (CRITICAL/HIGH):**
   - Remediate 2 CRITICAL hardcoded secrets (A02)
   - Patch 1 CRITICAL npm vulnerability (A06)
   - Fix 3 HIGH SQL injection flaws (A03)

2. **This Sprint (MEDIUM):**
   - Address 6 misconfigurations (A05)
   - Update 8 vulnerable dependencies (A06)
```

### Example 2: CIS Controls Implementation Group Report

```markdown
# CIS Controls v8.1 Implementation Group Report

**Scan Date:** 2025-10-16
**Current Maturity:** IG1 → IG2 (Target)

## Control Coverage

### ✅ IG1 Controls (Fully Implemented)

- **2.1 Asset Inventory:** SBOM generated via Syft (156 components)
- **4.1 Secure Configuration:** Checkov scans (14 IaC resources)
- **7.1 Vulnerability Management:** Trivy scans (13 CVEs detected)

### ⚠️ IG2 Controls (Partial Implementation)

- **16.2 SAST:** Semgrep enabled (8 findings)
  - **Gap:** Manual code review process (16.4) not documented
- **3.11 Data Protection:** Secrets scanning enabled (10 findings)
  - **Gap:** 10 unresolved hardcoded credentials

### ❌ IG3 Controls (Not Implemented)

- **18.5 Penetration Testing:** No evidence of regular pen tests
  - **Recommendation:** Enable ZAP DAST scans (automated) or engage third-party assessor

## Path to IG2 Maturity

1. Remediate all 10 hardcoded secrets (Control 3.11)
2. Document code review process (Control 16.4)
3. Implement quarterly vulnerability rescans (Control 7.1)
```

---

## Conclusion

This analysis recommends implementing **5 core frameworks** in JMo Security Audit Tool Suite v0.5.0:

1. **OWASP Top 10 2021** (with CWE Top 25 mappings) - Universal app-sec standard
2. **CIS Controls v8.1** - Tactical implementation guidance
3. **NIST Cybersecurity Framework 2.0** - Strategic risk management, maps to 50+ frameworks
4. **PCI DSS 4.0** - Mandatory for payment industry, large addressable market
5. **MITRE ATT&CK** - Threat modeling context, SOC/red team adoption

These frameworks provide:

- **Maximum coverage** across SAST/secrets/SCA/IaC/container scanning
- **Minimal redundancy** (complementary, not overlapping)
- **Industry recognition** (required for compliance, RFPs, audits)
- **Practical mappings** (clear rule → framework mappings)

Deferred frameworks (ISO 27001, SOC 2, HITRUST, FedRAMP) can be added in v0.6.0+ based on customer demand.

---

**Document Metadata:**

- **Author:** Claude Code (Anthropic)
- **Research Date:** 2025-10-16
- **Frameworks Analyzed:** 12+
- **Primary Sources:** OWASP, NIST, CIS, MITRE, PCI SSC, ISO, CISA
- **Next Review:** Q2 2025 (OWASP Top 10 2024 release, CIS Controls updates)
