# IT Security Device Classifications Reference

**Version:** 2026-02-26

**Purpose:** Authoritative reference for classifying security data sources during CIM normalization. Used to assign a standardized `security_classification` to each sourcetype in the sourcetype inventory.

## How to Use This Reference

When classifying a sourcetype, select the most specific classification that matches the data source's primary security function. Use the **Acronym** as the `security_classification` value.

If a source spans multiple categories (e.g., a UTM device that includes firewall + IDS), classify by its primary function or use the broader classification (e.g., UTM). List up to 3 classifications if applicable.

---

## Endpoint & Network Security

| Acronym | Full Name | Description | Example Vendors / Products |
|---------|-----------|-------------|---------------------------|
| FW | Firewall | Network security devices that monitor and control incoming/outgoing traffic based on predefined rules. Acts as a barrier between trusted and untrusted networks. | Cisco ASA, Palo Alto NGFW, Fortinet FortiGate, Check Point FireWall-1, Juniper SRX Series |
| NGFW | Next-Generation Firewall | Firewalls with deep packet inspection, application awareness, and integrated threat prevention beyond traditional port/protocol filtering. | Palo Alto PA Series, Fortinet FortiGate, Check Point Quantum |
| IDS | Intrusion Detection System | Monitors network traffic for malicious activities or policy violations and generates alerts. | Snort, Cisco Firepower, Suricata, Zeek (Bro) |
| IPS | Intrusion Prevention System | Detects and actively blocks or prevents malicious network traffic. | Cisco Firepower IPS, Palo Alto Threat Prevention, Fortinet FortiGate IPS, Trend Micro TippingPoint |
| UTM | Unified Threat Management | All-in-one security devices providing multiple features including firewall, antivirus, IDS/IPS, and content filtering. | Fortinet FortiGate UTM, Sophos XG, WatchGuard Firebox, Cisco Meraki MX, SonicWall TZ |
| EDR | Endpoint Detection and Response | Detects and responds to threats on endpoint devices such as servers, laptops, and workstations. | CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne Singularity, Carbon Black |
| EPP | Endpoint Protection Platform | Provides antivirus, anti-malware, and baseline endpoint threat protection. | Symantec Endpoint Protection, McAfee Endpoint Security, Trend Micro Apex One |
| XDR | Extended Detection and Response | Correlates detection and response data across endpoint, network, cloud, and email for unified threat visibility. | Palo Alto Cortex XDR, Microsoft 365 Defender, Trend Micro Vision One |
| NDR | Network Detection and Response | Detects anomalies and threats via network traffic analysis and provides response capabilities. | ExtraHop Reveal(x), Darktrace, Vectra AI Cognito, Cisco Stealthwatch, Gigamon ThreatINSIGHT |
| NGAV | Next-Gen Antivirus | AI/ML-based antivirus that goes beyond traditional signature matching to detect unknown threats. | CrowdStrike, Cylance, SentinelOne, Carbon Black |
| NAC | Network Access Control | Restricts unauthorized devices and users from accessing a network, enforcing compliance with security policies. | Cisco ISE, Aruba ClearPass, Fortinet FortiNAC, Forescout CounterACT, Juniper Mist NAC |

---

## Identity & Access Management

| Acronym | Full Name | Description | Example Vendors / Products |
|---------|-----------|-------------|---------------------------|
| IAM | Identity and Access Management | Controls user access to resources and manages authentication and authorization. | Okta Identity Cloud, Microsoft Entra ID (Azure AD), Ping Identity, IBM Security Verify |
| PAM | Privileged Access Management | Controls, monitors, and audits elevated/privileged access rights. | CyberArk Privileged Access Manager, BeyondTrust, Thycotic Secret Server, Delinea |
| MFA | Multi-Factor Authentication | Requires multiple verification methods (knowledge, possession, inherence) for authentication. | Duo Security, RSA SecurID, Microsoft Authenticator, YubiKey |
| SSO | Single Sign-On | Enables one login credential to access multiple systems and applications. | Okta SSO, Ping Identity, OneLogin, Microsoft Entra ID |
| IdP | Identity Provider | Authenticates users and provides identity assertions for SSO/SAML/OIDC integrations. | Okta, Microsoft Entra ID, Ping Identity, Auth0 |
| VPN | Virtual Private Network | Creates secure, encrypted tunnels for remote network access. | Cisco AnyConnect, Palo Alto GlobalProtect, Fortinet FortiClient VPN, Juniper Pulse Secure, SonicWall SMA |

---

## Threat Intelligence, Monitoring & Response

| Acronym | Full Name | Description | Example Vendors / Products |
|---------|-----------|-------------|---------------------------|
| SIEM | Security Information and Event Management | Collects, correlates, and analyzes security events and logs from various sources for centralized monitoring, detection, and alerting. | Splunk Enterprise Security, IBM QRadar, Microsoft Sentinel, ArcSight, Sumo Logic |
| SOAR | Security Orchestration, Automation and Response | Automates security workflows, playbooks, and incident response processes. | Splunk SOAR (Phantom), Palo Alto XSOAR, IBM Resilient, Swimlane |
| TIP | Threat Intelligence Platform | Aggregates, analyzes, and distributes threat intelligence from multiple sources to identify risks and vulnerabilities. | ThreatQuotient, Anomali ThreatStream, Recorded Future, IBM X-Force, Palo Alto AutoFocus |
| UEBA | User and Entity Behavior Analytics | Detects anomalies and insider threats based on deviations from normal user and entity behavior patterns. | Exabeam, Securonix, Microsoft Sentinel UEBA, Splunk UBA |

---

## Cloud & Application Security

| Acronym | Full Name | Description | Example Vendors / Products |
|---------|-----------|-------------|---------------------------|
| CASB | Cloud Access Security Broker | Enforces security policies for cloud resource access, providing visibility and control over cloud applications. | Netskope, Microsoft Defender for Cloud Apps, Zscaler, Palo Alto Prisma |
| CSPM | Cloud Security Posture Management | Identifies misconfigurations, compliance violations, and security risks in cloud infrastructure. | Prisma Cloud, AWS Security Hub, Azure Defender, Wiz, Orca Security |
| CWPP | Cloud Workload Protection Platform | Protects cloud workloads including VMs, containers, and serverless functions. | Prisma Cloud, Aqua Security, Sysdig, Lacework |
| CNAPP | Cloud-Native Application Protection Platform | Combines CSPM and CWPP capabilities into a unified platform for cloud-native security. | Prisma Cloud, Wiz, Orca Security, Aqua Security |
| CTD | Cloud Threat Detection | Cloud-native services that detect threats, anomalous behavior, and policy violations across cloud accounts and workloads. | AWS GuardDuty, Azure Defender, Google Chronicle Security |
| WAF | Web Application Firewall | Filters, monitors, and blocks HTTP/HTTPS traffic to protect web applications against attacks like SQL injection and XSS. | F5 BIG-IP WAF, Imperva SecureSphere, Akamai Kona, Cloudflare WAF, Fortinet FortiWeb |
| DAST | Dynamic Application Security Testing | Tests running applications for vulnerabilities by simulating attacks. | Burp Suite, OWASP ZAP, Rapid7 InsightAppSec, Qualys WAS |
| SAST | Static Application Security Testing | Analyzes source code, bytecode, or binaries for security flaws without executing the application. | Checkmarx, Veracode, SonarQube, Fortify |
| RASP | Runtime Application Self-Protection | Monitors and protects applications from within during runtime by detecting and blocking attacks in real time. | Contrast Security, Imperva RASP, Signal Sciences |
| SWG | Secure Web Gateway | Filters web traffic, enforces security policies, and protects against web-based threats. | Zscaler Internet Access, Forcepoint SWG, Cisco Umbrella, Palo Alto Prisma Access, Symantec WSS |

---

## Infrastructure, Data & Asset Protection

| Acronym | Full Name | Description | Example Vendors / Products |
|---------|-----------|-------------|---------------------------|
| VMS | Vulnerability Management System | Scans, identifies, and tracks software and hardware vulnerabilities for remediation. | Tenable Nessus, Qualys VMDR, Rapid7 InsightVM, CrowdStrike Spotlight |
| DLP | Data Loss Prevention | Monitors and prevents sensitive data from leaving an organization's network through unauthorized channels. | Symantec DLP, McAfee Total Protection for DLP, Digital Guardian, Forcepoint DLP, Microsoft Purview |
| EASM | External Attack Surface Management | Discovers and identifies exposed digital assets, shadow IT, and external-facing vulnerabilities for remediation. | Mandiant Advantage, CrowdStrike Falcon Surface, Microsoft Defender EASM, Censys |
| ESG | Email Security Gateway | Filters and secures email communications by blocking spam, phishing, and malicious attachments. | Proofpoint, Cisco Secure Email, Barracuda Email Security, Mimecast, Fortinet FortiMail |
| DT | Deception Technology | Uses decoys, honeypots, and traps to detect, analyze, and divert potential attackers. | Attivo ThreatDefend, Acalvio ShadowPlex, TrapX DeceptionGrid, Fidelis Deception |

---

## Governance, Risk & Compliance

| Acronym | Full Name | Description | Example Vendors / Products |
|---------|-----------|-------------|---------------------------|
| GRC | Governance, Risk and Compliance | Frameworks and platforms for managing IT risk, regulatory alignment, and organizational compliance. | ServiceNow GRC, RSA Archer, OneTrust, MetricStream |
| DRM | Digital Rights Management | Controls usage, distribution, and access to digital content and intellectual property. | Microsoft Azure Information Protection, Adobe DRM, Vitrium |
| PKI | Public Key Infrastructure | Enables encryption, digital signatures, and certificate management for secure communications. | DigiCert, Venafi, Microsoft AD CS, Let's Encrypt |

---

## Security Simulation & Architecture

| Acronym | Full Name | Description | Example Vendors / Products |
|---------|-----------|-------------|---------------------------|
| BAS | Breach and Attack Simulation | Emulates real-world attacks against an organization's defenses to test detection and response capabilities. | SafeBreach, AttackIQ, Cymulate, Picus Security |
| ZTA | Zero Trust Architecture | Security model requiring continuous verification for all users, devices, and connections regardless of location. | Zscaler, Palo Alto Prisma, Okta, Illumio |

---

## Quick Reference (Alphabetical)

| Acronym | Full Name | Category |
|---------|-----------|----------|
| BAS | Breach and Attack Simulation | Security Simulation & Architecture |
| CASB | Cloud Access Security Broker | Cloud & Application Security |
| CNAPP | Cloud-Native Application Protection Platform | Cloud & Application Security |
| CSPM | Cloud Security Posture Management | Cloud & Application Security |
| CTD | Cloud Threat Detection | Cloud & Application Security |
| CWPP | Cloud Workload Protection Platform | Cloud & Application Security |
| DAST | Dynamic Application Security Testing | Cloud & Application Security |
| DLP | Data Loss Prevention | Infrastructure, Data & Asset Protection |
| DRM | Digital Rights Management | Governance, Risk & Compliance |
| DT | Deception Technology | Infrastructure, Data & Asset Protection |
| EASM | External Attack Surface Management | Infrastructure, Data & Asset Protection |
| EDR | Endpoint Detection and Response | Endpoint & Network Security |
| EPP | Endpoint Protection Platform | Endpoint & Network Security |
| ESG | Email Security Gateway | Infrastructure, Data & Asset Protection |
| FW | Firewall | Endpoint & Network Security |
| GRC | Governance, Risk and Compliance | Governance, Risk & Compliance |
| IAM | Identity and Access Management | Identity & Access Management |
| IdP | Identity Provider | Identity & Access Management |
| IDS | Intrusion Detection System | Endpoint & Network Security |
| IPS | Intrusion Prevention System | Endpoint & Network Security |
| MFA | Multi-Factor Authentication | Identity & Access Management |
| NAC | Network Access Control | Endpoint & Network Security |
| NDR | Network Detection and Response | Endpoint & Network Security |
| NGAV | Next-Gen Antivirus | Endpoint & Network Security |
| NGFW | Next-Generation Firewall | Endpoint & Network Security |
| PAM | Privileged Access Management | Identity & Access Management |
| PKI | Public Key Infrastructure | Governance, Risk & Compliance |
| RASP | Runtime Application Self-Protection | Cloud & Application Security |
| SAST | Static Application Security Testing | Cloud & Application Security |
| SIEM | Security Information and Event Management | Threat Intelligence, Monitoring & Response |
| SOAR | Security Orchestration, Automation and Response | Threat Intelligence, Monitoring & Response |
| SSO | Single Sign-On | Identity & Access Management |
| SWG | Secure Web Gateway | Cloud & Application Security |
| TIP | Threat Intelligence Platform | Threat Intelligence, Monitoring & Response |
| UEBA | User and Entity Behavior Analytics | Threat Intelligence, Monitoring & Response |
| UTM | Unified Threat Management | Endpoint & Network Security |
| VMS | Vulnerability Management System | Infrastructure, Data & Asset Protection |
| VPN | Virtual Private Network | Identity & Access Management |
| WAF | Web Application Firewall | Cloud & Application Security |
| XDR | Extended Detection and Response | Endpoint & Network Security |
| ZTA | Zero Trust Architecture | Security Simulation & Architecture |

---

## Classification Guidelines

When assigning `security_classification` to a sourcetype:

1. Use the acronym as the value (e.g., `CTD`, `EDR`, `SIEM`)
2. Match by **function**, not platform — classify by what the device does, not where it runs
3. Be specific — prefer `EDR` over `EPP` if the source provides detection and response telemetry, not just antivirus alerts
4. Use `CTD` for cloud-native threat detection services (AWS GuardDuty, Azure Defender alerts, Google Chronicle detections)
5. Use `CSPM` for cloud configuration/posture findings (AWS Config, Azure Policy, GCP Security Command Center)
6. List up to 3 classifications for multi-function devices, separated by commas
7. Use `N/A` for non-security sourcetypes; use `Unknown` if there is insufficient information to classify
