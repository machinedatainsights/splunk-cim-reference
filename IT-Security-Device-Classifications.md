# 🔐 IT Security Device Classifications

A comprehensive list of classifications, descriptions, and prominent vendors/devices.

## 🔐 Security Technology Classifications with CIM Data Models

| #  | Classification | Description | Examples (Vendors & Devices) | Applicable CIM Data Models |
|----|----------------|-------------|------------------------------|----------------------------|
| 1  | Firewalls                                | Controls inbound and outbound network traffic based on security rules.                              | Cisco ASA, Palo Alto NGFW, Fortinet FortiGate, Check Point, Juniper SRX                                                   | Network_Traffic, Network_Sessions, Intrusion_Detection                                     |
| 2  | IDS / IPS                                 | Monitors and blocks malicious network activity.                                                     | Snort, Cisco Firepower IDS/IPS, Fortinet IPS, Trend Micro TippingPoint                                                    | Intrusion_Detection, Event_Signatures, Alerts                                              |
| 3  | Unified Threat Management (UTM)          | Combines multiple security functions into a single device.                                           | Fortinet FortiGate UTM, Sophos XG, Cisco Meraki MX, SonicWall TZ                                                          | Network_Traffic, Intrusion_Detection, Malware                                              |
| 4  | Web Application Firewall (WAF)           | Protects web applications from HTTP-based attacks.                                                  | F5 BIG-IP, Imperva SecureSphere, Cloudflare WAF, Fortinet FortiWeb                                                        | Web, Network_Traffic, Intrusion_Detection                                                  |
| 5  | Network Access Control (NAC)             | Controls device access to the network.                                                              | Cisco ISE, Aruba ClearPass, Fortinet FortiNAC, Forescout CounterACT                                                       | Endpoint, Inventory, Authentication                                                        |
| 6  | Endpoint Protection / Detection (EPP/EDR)| Protects endpoint devices from threats and monitors behavior.                                       | CrowdStrike Falcon, Microsoft Defender, SentinelOne, Symantec, McAfee                                                     | Endpoint, Malware, Intrusion_Detection, Alerts                                             |
| 7  | SIEM                                      | Aggregates and analyzes security events and logs.                                                   | Splunk ES, IBM QRadar, ArcSight, Microsoft Sentinel                                                                       | Splunk Audit Logs (internal), Alerts, Risk (ES model), All CIM models used for ingestion  |
| 8  | Email Security Gateways                  | Filters and protects email communications.                                                          | Proofpoint, Mimecast, Cisco Secure Email, Fortinet FortiMail                                                              | Email, Malware, Alerts                                                                     |
| 9  | Secure Web Gateways (SWG)                | Filters web traffic and protects against web-based threats.                                         | Zscaler, Forcepoint, Cisco Umbrella, Palo Alto Prisma Access                                                              | Web, Network_Traffic, Malware                                                              |
| 10 | Data Loss Prevention (DLP)               | Prevents unauthorized data exfiltration.                                                            | Symantec DLP, McAfee DLP, Microsoft Purview, Forcepoint DLP                                                               | Data Loss Prevention, Data_Access                                                          |
| 11 | Identity and Access Management (IAM)     | Controls user identities and resource access.                                                       | Okta, Microsoft Entra ID, Ping, CyberArk PAM, IBM Verify                                                                  | Authentication, Change, Alerts                                                             |
| 12 | Virtual Private Network (VPN)            | Provides secure remote access via encrypted tunnels.                                                | Cisco AnyConnect, Palo Alto GlobalProtect, Fortinet FortiClient VPN                                                       | Network_Sessions, Authentication, Network_Traffic                                          |
| 13 | Threat Intelligence Platforms (TIP)      | Aggregates and disseminates threat intel.                                                           | ThreatQ, Anomali, IBM X-Force, Recorded Future                                                                            | Alerts, Intrusion_Detection, Event_Signatures (custom mapping may be required)             |
| 14 | Network Detection and Response (NDR)     | Detects threats from deep network traffic analysis.                                                 | ExtraHop Reveal(x), Darktrace, Vectra AI Cognito, Cisco Stealthwatch                                                      | Intrusion_Detection, Network_Traffic, Network_Sessions                                     |
| 15 | Deception Technology                     | Uses decoys and traps to detect adversary movement.                                                 | Attivo ThreatDefend, Acalvio ShadowPlex, TrapX, Smokescreen IllusionBLACK                                                 | Intrusion_Detection, Alerts, Event_Signatures                                              |

## 🔍 Common Sourcetypes by Security Device Classification

| Classification                           | Common Splunk Sourcetypes |
| ---------------------------------------- | ------------------------- |
| **Firewall**                              | pan:log, cisco:asa, fortigate, juniper, checkpoint            |
| **Intrusion Detection System (IDS)**      | snort, sourcetype=ids, sourcefire, suricata                   |
| **Intrusion Prevention System (IPS)**     | cisco:sourcefire, paloalto:threat, fortinet:utm               |
| **Web Proxy / Secure Web Gateway**        | bluecoat:proxysg, zscalerenrich, symantec:webgateway, squid   |
| **Endpoint Detection & Response (EDR)**   | crowdstrike:event, carbonblack:json, sentinelone:events       |
| **SIEM (Log Aggregators)**                | Not applicable – Splunk is the SIEM                           |
| **Email Security Gateway**                | proofpoint:tap, o365:exchange, mimecast, barracuda            |
| **Data Loss Prevention (DLP)**            | symantec:dpl, forcepoint:dpl, o365:dataloss                   |
| **Threat Intelligence Platform (TIP)**    | threatconnect:event, misp:json, anomali:staxx                 |
| **Network Access Control (NAC)**          | cisco:ise, aruba:clearpass                                    |
| **Vulnerability Management**              | nessus, qualys:hostDetection, rapid7:insightvm                |
| **Cloud Security Posture Management (CSPM)** | aws:config, gcp:securitycenter, azure:securitycenter       |
| **Identity and Access Management (IAM)**  | okta:auth, o365:management:activity, azure:activity           |
| **Multi-Factor Authentication (MFA)**     | duo:authentication, okta:auth, azure:signinlogs              |
| **Deception Technology**                  | attivo:log, trapx:alert, illusive:trap                        |

EOF
