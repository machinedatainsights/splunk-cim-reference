# Splunk CIM Data Model — Field Catalog

**Purpose:** a catalog of every Splunk Common Information Model (CIM) field, by data model and dataset — to reconcile a generated or third-party add-on field-for-field against what the model actually defines.  

**Source:** `splunk_data_model_objects_fields_850.csv` (Splunk CIM 8.5.0)  
**Generated:** May 19, 2026  
**Scope:** 1474 fields · 27 models · 139 datasets  

**Status:** `Req` = required · `Rec` = recommended (the dataset should populate it) · `Opt` = optional.  
**Tags** match events into a dataset (not sourcetype); a tag not listed here pulls events into *no* known dataset.  
**Child datasets** (dotted names) list only the fields they add and also inherit the parent’s fields + tag constraint. Fields described “Auto-set by ES asset/identity correlation” must **not** be extracted by an add-on. `(Eval)`/`(Rex)`/`(Lookup)` = the model derives the field that way.  

---

## Models

- [Alerts](#alerts) — 1 dataset(s), 30 fields
- [Application_State](#application-state) — 4 dataset(s), 25 fields
- [Authentication](#authentication) — 1 dataset(s), 41 fields
- [Certificates](#certificates) — 2 dataset(s), 47 fields
- [Change](#change) — 4 dataset(s), 49 fields
- [Change_Analysis](#change-analysis) — 3 dataset(s), 40 fields
- [Compute_Inventory](#compute-inventory) — 9 dataset(s), 57 fields
- [DLP](#dlp) — 1 dataset(s), 37 fields
- [Data_Access](#data-access) — 1 dataset(s), 41 fields
- [Databases](#databases) — 8 dataset(s), 76 fields
- [Email](#email) — 2 dataset(s), 53 fields
- [Endpoint](#endpoint) — 5 dataset(s), 177 fields
- [Event_Signatures](#event-signatures) — 1 dataset(s), 9 fields
- [Interprocess_Messaging](#interprocess-messaging) — 1 dataset(s), 35 fields
- [Intrusion_Detection](#intrusion-detection) — 1 dataset(s), 35 fields
- [JVM](#jvm) — 7 dataset(s), 46 fields
- [Malware](#malware) — 2 dataset(s), 44 fields
- [Network_Resolution](#network-resolution) — 1 dataset(s), 32 fields
- [Network_Sessions](#network-sessions) — 2 dataset(s), 29 fields
- [Network_Traffic](#network-traffic) — 1 dataset(s), 66 fields
- [Performance](#performance) — 9 dataset(s), 49 fields
- [Splunk_Audit](#splunk-audit) — 6 dataset(s), 79 fields
- [Splunk_CIM_Validation](#splunk-cim-validation) — 58 dataset(s), 256 fields
- [Ticket_Management](#ticket-management) — 4 dataset(s), 28 fields
- [Updates](#updates) — 2 dataset(s), 21 fields
- [Vulnerabilities](#vulnerabilities) — 1 dataset(s), 28 fields
- [Web](#web) — 2 dataset(s), 44 fields

---

## Alerts

### `Alerts`

**Object** `Alerts` · **Parent** `BaseEvent` · **Fields** 30 · **Tags** `alert`  
**Constraint** ``(`cim_Alerts_indexes`) tag=alert``

| Field | St | Type | Description |
|---|:--:|---|---|
| `app` | Rec | string | The system, service, or application that generated the alert event. Examples incl… (Eval) |
| `dest` | Rec | string | The object that is the 'target' of the alert event. Examples include an email add… (Eval) |
| `severity` | Rec | string | The severity of the alert event. Note: This field is a string. Specific values ar… (Eval) |
| `signature_id` | Rec | string | The vendor specific policy or rule that generated the alert event, such as 'Polic… (Eval) |
| `src` | Rec | string | The object that is the 'actor' of the alert event. You can alias or extract this… (Eval) |
| `type` | Rec | string | The alert event type. (Eval) |
| `user` | Rec | string | The user involved in the alert event. (Eval) |
| `body` | Opt | string | This field is deprecated in favor of 'description'. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `description` | Opt | string | The description of the alert event. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_type` | Opt | string | The type of the destination object, such as 'instance', 'storage', 'firewall'. |
| `id` | Opt | string | The unique identifier of the alert event. |
| `mitre_technique_id` | Opt | string | The MITRE ATT&CK technique ID of the alert event, searchable at https://attack.mi… |
| `severity_id` | Opt | string | The numeric or vendor specific severity indicator corresponding to the event seve… |
| `signature` | Opt | string | The human-friendly title of the alert event, such as 'API GetAccountPasswordPolic… |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_type` | Opt | string | The type of the source object, such as 'instance', 'storage', 'firewall'. |
| `subject` | Opt | string | This field is deprecated in favor of 'signature'. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_name` | Opt | string | The user_name of user involved in the alert event. (Eval) |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `vendor_account` | Opt | string | The account associated with the alert event. |
| `vendor_region` | Opt | string | The data center region involved in the alert event, such as us-west-2. |

**Prescribed values**  
`severity` = critical, high, medium, low, informational, unknown  
`type` = alarm, alert, event, task, warning, unknown  

---

## Application_State

### `All_Application_State`

**Object** `All_Application_State` · **Parent** `BaseEvent` · **Fields** 14 · **Tags** `listening`, `port`, `process`, `report`, `service`  
**Constraint** ``(`cim_Application_State_indexes`) (tag=listening tag=port) OR (tag=process tag=report) OR (tag=service tag=report)``

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Rec | string | The compute resource where the service is installed. You can alias this from more… (Eval) |
| `process` | Rec | string | The name of a process or service file, such as sqlsrvr.exe or httpd. Note: This f… (Eval) |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_requires_av` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_timesync` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_update` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `process_name` | Opt | string | The name of a process. (Rex) |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user` | Opt | string | The user account the service is running as, such as System or httpdsvc. |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

### `All_Application_State.Ports`

**Object** `Ports` · **Parent** `All_Application_State` · **Fields** 3 · **Tags** `listening`, `port`  
**Constraint** `tag=listening tag=port`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest_port` | Rec | number | Network ports communicated to by the process, such as 53. (Eval) |
| `transport` | Rec | string | The network ports listened to by the application process, such as tcp, udp, etc. (Eval) |
| `transport_dest_port` | Opt | string | Calculated as transport/dest_port, such as tcp/53. (Eval) |

### `All_Application_State.Processes`

**Object** `Processes` · **Parent** `All_Application_State` · **Fields** 4 · **Tags** `process`, `report`  
**Constraint** `tag=process tag=report`

| Field | St | Type | Description |
|---|:--:|---|---|
| `cpu_load_mhz` | Opt | number | CPU Load in megahertz. |
| `cpu_load_percent` | Opt | number | CPU Load in percent. |
| `cpu_time` | Opt | string | CPU Time. |
| `mem_used` | Opt | number | Memory used in bytes. |

### `All_Application_State.Services`

**Object** `Services` · **Parent** `All_Application_State` · **Fields** 4 · **Tags** `service`, `report`  
**Constraint** `tag=service tag=report`

| Field | St | Type | Description |
|---|:--:|---|---|
| `service` | Rec | string | The name of the service, such as SQL Server or Apache Web Server. Note: This fiel… (Eval) |
| `service_id` | Rec | string | A numeric indicator for a service. (Eval) |
| `start_mode` | Rec | string | The start mode for the service. (Eval) |
| `status` | Rec | string | The status of the service. (Eval) |

**Prescribed values**  
`start_mode` = disabled, manual, auto  
`status` = critical, started, stopped, warning  

---

## Authentication

### `Authentication`

**Object** `Authentication` · **Parent** `BaseEvent` · **Fields** 41 · **Tags** `authentication`  
**Constraint** ``(`cim_Authentication_indexes`) tag=authentication NOT (action=success user=*$)``

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | The action performed on the resource. (Eval) |
| `app` | Rec | string | The application involved in the event, such as ssh, splunk, win:local. (Eval) |
| `dest` | Rec | string | The target involved in the authentication. You can alias this from more specific… (Eval) |
| `src` | Rec | string | The source involved in the authentication. In the case of endpoint protection aut… (Eval) |
| `src_user` | Rec | string | In privilege escalation events, src_user represents the user who initiated the pr… (Eval) |
| `user` | Rec | string | The name of the user involved in the event, or who initiated the event. For authe… (Eval) |
| `authentication_method` | Opt | string | The method used to authenticate the request such as SAML, FIDO, or MFA. |
| `authentication_service` | Opt | string | The service used to authenticate the request such as Okta, or ActiveDirectory |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_nt_domain` | Opt | string | The name of the Active Directory used by the authentication target, if applicable. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `duration` | Opt | number | The amount of time for the completion of the authentication event, in seconds. |
| `process` | Opt | string | Full path and the name of the executable for the process that attempted the logon… |
| `reason` | Opt | string | The human-readable message associated with the authentication action (success or… |
| `reason_id` | Opt | string | The reason why logon failed. For example "0xC0000234". |
| `response_time` | Opt | number | The amount of time it took to receive a response in the authentication event, in… |
| `result` | Opt | string | The result of the authentication attempt for audittrailv2 sourcetypes. (Eval) |
| `session_id` | Opt | string | The unique identifier assigned to the login session. |
| `signature` | Opt | string | A human-readable signature name. |
| `signature_id` | Opt | string | The unique identifier or event code of the event signature. |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_nt_domain` | Opt | string | The name of the Active Directory used by the authentication source, if applicable. |
| `src_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_id` | Opt | string | The unique id of the user who initiated the privilege escalation. This field is u… |
| `src_user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_role` | Opt | string | The role of the user who initiated the privilege escalation. This field is unnece… |
| `src_user_type` | Opt | string | The type of the user who initiated the privilege escalation. This field is unnece… |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user_agent` | Opt | string | The user agent through which the request was made, such as Mozilla/5.0 (Macintosh… |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_id` | Opt | string | The unique id of the user involved in the event. For authentication privilege esc… |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_role` | Opt | string | The role of the user involved in the event, or who initiated the event. For authe… |
| `user_type` | Opt | string | The type of the user involved in the event or who initiated the event, such as IA… |
| `vendor_account` | Opt | string | The account that manages the user that initiated the request. |

**Prescribed values**  
`action` = success, failure, pending, error  

---

## Certificates

### `All_Certificates`

**Object** `All_Certificates` · **Parent** `BaseEvent` · **Fields** 15 · **Tags** `certificate`  
**Constraint** ``(`cim_Certificates_indexes`) tag=certificate``

| Field | St | Type | Description |
|---|:--:|---|---|
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest` | Opt | string | The target in the certificate management event. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | The category of the target, such as email_server or SOX-compliant. This field is… |
| `dest_port` | Opt | number | The port number of the target. |
| `dest_priority` | Opt | string | The priority of the target. |
| `duration` | Opt | number | The amount of time for the completion of the certificate management event, in sec… |
| `response_time` | Opt | number | The amount of time it took, in seconds, to receive a response in the certificate… |
| `src` | Opt | string | The source involved in the certificate management event. You can alias this from… |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_category` | Opt | string | The category of the certificate management source, such as email_server or SOX-co… |
| `src_port` | Opt | number | The port number of the source. |
| `src_priority` | Opt | string | The priority of the certificate management source. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `transport` | Opt | string | The transport protocol of the Network Traffic involved with this certificate. |

### `All_Certificates.SSL`

**Object** `SSL` · **Parent** `All_Certificates` · **Fields** 32 · **Tags** `ssl`, `tls`  
**Constraint** `(tag=ssl OR tag=tls)`

| Field | St | Type | Description |
|---|:--:|---|---|
| `ssl_end_time` | Rec | timestamp | The expiry time of the certificate. |
| `ssl_hash` | Rec | string | The hash of the certificate. (Eval) |
| `ssl_issuer` | Rec | string | The certificate issuer's RFC2253 Distinguished Name. (Eval) |
| `ssl_issuer_common_name` | Rec | string | The certificate issuer's common name. (Eval) |
| `ssl_issuer_email_domain` | Rec | string | The domain name contained within the certificate issuer's email address. (Rex) |
| `ssl_serial` | Rec | string | The certificate's serial number. |
| `ssl_start_time` | Rec | timestamp | This is the start date and time for this certificate's validity. |
| `ssl_subject` | Rec | string | The certificate owner's RFC2253 Distinguished Name. (Eval) |
| `ssl_subject_common_name` | Rec | string | The certificate subject's common name. (Eval) |
| `ssl_subject_email_domain` | Rec | string | The domain name contained within the certificate subject's email address. (Rex) |
| `ssl_engine` | Opt | string | The name of the signature engine that created the certificate. |
| `ssl_is_valid` | Opt | boolean | Indicator of whether the ssl certificate is valid or not. (Eval) |
| `ssl_issuer_email` | Opt | string | The certificate issuer's email address. |
| `ssl_issuer_locality` | Opt | string | The certificate issuer's locality. |
| `ssl_issuer_organization` | Opt | string | The certificate issuer's organization. |
| `ssl_issuer_state` | Opt | string | The certificate issuer's state of residence. |
| `ssl_issuer_street` | Opt | string | The certificate issuer's street address. |
| `ssl_issuer_unit` | Opt | string | The certificate issuer's organizational unit. |
| `ssl_name` | Opt | string | The name of the ssl certificate. |
| `ssl_policies` | Opt | string | The Object Identification Numbers of the certificate's policies in a comma separa… |
| `ssl_publickey` | Opt | string | The certificate's public key. |
| `ssl_publickey_algorithm` | Opt | string | The algorithm used to create the public key. |
| `ssl_session_id` | Opt | string | The session identifier for this certificate. |
| `ssl_signature_algorithm` | Opt | string | The algorithm used by the Certificate Authority to sign the certificate. |
| `ssl_subject_email` | Opt | string | The certificate owner's e-mail address. |
| `ssl_subject_locality` | Opt | string | The certificate owner's locality. |
| `ssl_subject_organization` | Opt | string | The certificate owner's organization. |
| `ssl_subject_state` | Opt | string | The certificate owner's state of residence. |
| `ssl_subject_street` | Opt | string | The certificate owner's street address. |
| `ssl_subject_unit` | Opt | string | The certificate owner's organizational unit. |
| `ssl_validity_window` | Opt | number | The length of time, in seconds, for which this certificate is valid. (Eval) |
| `ssl_version` | Opt | string | The ssl version of this certificate. |

**Prescribed values**  
`ssl_is_valid` = true, false, 1, 0  

---

## Change

### `All_Changes`

**Object** `All_Changes` · **Parent** `BaseEvent` · **Fields** 32 · **Tags** `change`  
**Constraint** ``(`cim_Change_indexes`) tag=change``

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | The action attempted on the resource, regardless of success or failure. (Eval) |
| `change_type` | Rec | string | The type of change, such as filesystem or AAA (authentication, authorization, and… (Eval) |
| `command` | Rec | string | The command that initiated the change. (Eval) |
| `dest` | Rec | string | The resource where change occurred. You can alias this from more specific fields… (Eval) |
| `dvc` | Rec | string | The device that reported the change, if applicable, such as a FIP or CIM server… (Eval) |
| `object` | Rec | string | Name of the affected object on the resource, such as a router interface, user acc… (Eval) |
| `object_attrs` | Rec | string | The attributes that were updated on the updated resource object, if applicable. (Eval) |
| `object_category` | Rec | string | Generic name for the class of the updated resource object. Expected values may be… (Eval) |
| `object_id` | Rec | string | The unique updated resource object ID as presented to the system, if applicable… (Eval) |
| `object_path` | Rec | string | The path of the modified resource object, if applicable, such as a file, director… (Eval) |
| `result` | Rec | string | The vendor-specific result of a change, or clarification of an action status. For… (Eval) |
| `result_id` | Rec | string | A result indicator for an action status. (Eval) |
| `src` | Rec | string | The resource where the change was originated. You can alias this from more specif… (Eval) |
| `status` | Rec | string | Status of the update. (Eval) |
| `user` | Rec | string | The user or entity performing the change. For account changes, this is the accoun… (Eval) |
| `vendor_product` | Rec | string | The vendor and product or service that detected the change. This field can be aut… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user_agent` | Opt | string | The user agent through which the request was made, such as Mozilla/5.0 (Macintosh… |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_name` | Opt | string | The user name of the user or entity performing the change. For account changes, t… (Eval) |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_type` | Opt | string | The type of the user involved in the event or who initiated the event, such as IA… |
| `vendor_account` | Opt | string | The account associated with the change. |
| `vendor_region` | Opt | string | The data center region where the change occurred, such as us-west-2. |

**Prescribed values**  
`action` = acl_modified, cleared, created, deleted, modified, stopped, lockout, read, logoff, updated, started, restarted, unlocked  
`status` = success, failure  

### `All_Changes.Network_Changes`

**Object** `Network_Changes` · **Parent** `All_Changes` · **Fields** 7 · **Tags** `network`  
**Constraint** `tag=network`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest_ip_range` | Opt | string | For network events, the outgoing traffic for a specific destination IP address ra… |
| `dest_port_range` | Opt | string | For network events, this field represents destination port or range. For example… |
| `direction` | Opt | string | For network events, this field represents whether the traffic is inbound or outbo… |
| `protocol` | Opt | string | This field represents the protocol for the network event rule. |
| `rule_action` | Opt | string | For network events, this field represents whether to allow or deny traffic. |
| `src_ip_range` | Opt | string | For network events, this field represents the incoming traffic from a specific so… |
| `src_port_range` | Opt | string | For network events, this field represents source port or range. For example, 80 o… |

### `All_Changes.Account_Management`

**Object** `Account_Management` · **Parent** `All_Changes` · **Fields** 8 · **Tags** `account`  
**Constraint** `tag=account`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest_nt_domain` | Rec | string | The NT domain of the destination, if applicable. (Eval) |
| `src_nt_domain` | Rec | string | The NT domain of the source, if applicable. (Eval) |
| `src_user` | Rec | string | For account changes, the user or entity performing the change. (Eval) |
| `src_user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_name` | Opt | string | For account changes, the user name of the user or entity performing the change. (Eval) |
| `src_user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_type` | Opt | string | For account management events, this should represent the type of the user changed… |

### `All_Changes.Instance_Changes`

**Object** `Instance_Changes` · **Parent** `All_Changes` · **Fields** 2 · **Tags** `instance`  
**Constraint** `tag=instance`

| Field | St | Type | Description |
|---|:--:|---|---|
| `image_id` | Rec | string | For create instance events, this field represents the image ID used for creating… (Eval) |
| `instance_type` | Rec | string | For create instance events, this field represents the type of instance to build s… (Eval) |

---

## Change_Analysis

### `All_Changes`

**Object** `All_Changes` · **Parent** `BaseEvent` · **Fields** 26 · **Tags** `change`  
**Constraint** ``(`cim_Change_Analysis_indexes`) tag=change``

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | The action performed on the resource. (Eval) |
| `change_type` | Rec | string | The type of change, such as filesystem or AAA (authentication, authorization, and… (Eval) |
| `command` | Rec | string | The command that initiated the change. (Eval) |
| `dest` | Rec | string | The resource where change occurred. You can alias this from more specific fields… (Eval) |
| `dvc` | Rec | string | The device that reported the change, if applicable, such as a FIP or CIM server… (Eval) |
| `object` | Rec | string | Name of the affected object on the resource, such as a router interface, user acc… (Eval) |
| `object_attrs` | Rec | string | The attributes that were updated on the updated resource object, if applicable. (Eval) |
| `object_category` | Rec | string | Generic name for the class of the updated resource object. Expected values may be… (Eval) |
| `object_id` | Rec | string | The unique updated resource object ID as presented to the system, if applicable… (Eval) |
| `object_path` | Rec | string | The path of the modified resource object, if applicable, such as a file, director… (Eval) |
| `result` | Rec | string | The vendor-specific result of a change, or clarification of an action status. For… (Eval) |
| `result_id` | Rec | string | A result indicator for an action status. (Eval) |
| `src` | Rec | string | The resource where the change was originated. You can alias this from more specif… (Eval) |
| `status` | Rec | string | Status of the update. (Eval) |
| `user` | Rec | string | The user or entity performing the change. For account changes, this is the accoun… (Eval) |
| `vendor_product` | Rec | string | The vendor and product or service that detected the change. This field can be aut… (Eval) |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

**Prescribed values**  
`action` = acl_modified, cleared, created, deleted, modified, read, stopped, updated  
`change_type` = restart  
`object_category` = directory, file, group, registry, user  
`result` = lockout  
`status` = success, failure  

### `Endpoint_Changes.Filesystem_Changes`

**Object** `Filesystem_Changes` · **Parent** `Endpoint_Changes` · **Fields** 8  
**Constraint** `(object_category=file OR object_category=directory)`

| Field | St | Type | Description |
|---|:--:|---|---|
| `file_access_time` | Rec | timestamp | The time the file (the object of the event) was accessed. (Eval) |
| `file_acl` | Rec | string | Access controls associated with the file affected by the event. (Eval) |
| `file_create_time` | Rec | timestamp | The time the file (the object of the event) was created. (Eval) |
| `file_hash` | Rec | string | A cryptographic identifier assigned to the file object affected by the event. (Eval) |
| `file_modify_time` | Rec | timestamp | The time the file (the object of the event) was altered. (Eval) |
| `file_name` | Rec | string | The name of the file that is the object of the event (without location informatio… (Eval) |
| `file_path` | Rec | string | The location of the file that is the object of the event, in local file and direc… (Eval) |
| `file_size` | Rec | number | The size of the file that is the object of the event, in kilobytes. (Eval) |

### `All_Changes.Account_Management`

**Object** `Account_Management` · **Parent** `All_Changes` · **Fields** 6 · **Tags** `account`  
**Constraint** `tag=account`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest_nt_domain` | Rec | string | The NT domain of the destination, if applicable. (Eval) |
| `src_nt_domain` | Rec | string | The NT domain of the source, if applicable. (Eval) |
| `src_user` | Rec | string | For account changes, the user or entity performing the change. (Eval) |
| `src_user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

---

## Compute_Inventory

### `All_Inventory`

**Object** `All_Inventory` · **Parent** `BaseEvent` · **Fields** 14 · **Tags** `inventory`, `cpu`, `memory`, `network`, `storage`, `system`, `version`, `user`, `virtual`  
**Constraint** ``(`cim_Compute_Inventory_indexes`) tag=inventory (tag=cpu OR tag=memory OR tag=network OR tag=storage OR (tag=system tag=version) OR tag=user OR tag=virtual)``

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Rec | string | The system where the data originated, the source of the event. You can alias this… (Eval) |
| `vendor_product` | Rec | string | The vendor and product name of the resource, such as Cisco Catalyst 3850. This fi… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `description` | Opt | string | The description of the inventory system. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | The priority of the system where the data originated. |
| `enabled` | Opt | boolean | Indicates whether the resource is enabled or disabled. |
| `family` | Opt | string | The product family of the resource, such as 686_64 or RISC. |
| `hypervisor_id` | Opt | string | The hypervisor identifier, if applicable. |
| `serial` | Opt | string | The serial number of the resource. |
| `status` | Opt | string | The current reported state of the resource. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `version` | Opt | string | The version of a computer resource, such as 2008r2 or 3.0.0. |

### `All_Inventory.CPU`

**Object** `CPU` · **Parent** `All_Inventory` · **Fields** 3 · **Tags** `cpu`  
**Constraint** `tag=cpu`

| Field | St | Type | Description |
|---|:--:|---|---|
| `cpu_cores` | Rec | number | The number of CPU cores reported by the resource (total, not per CPU). |
| `cpu_count` | Rec | number | The number of CPUs reported by the resource. |
| `cpu_mhz` | Rec | number | The maximum speed of the CPU reported by the resource (in megahertz). |

### `All_Inventory.Memory`

**Object** `Memory` · **Parent** `All_Inventory` · **Fields** 1 · **Tags** `memory`  
**Constraint** `tag=memory`

| Field | St | Type | Description |
|---|:--:|---|---|
| `mem` | Rec | number | The total amount of memory installed in or allocated to the resource, in megabyte… |

### `All_Inventory.Network`

**Object** `Network` · **Parent** `All_Inventory` · **Fields** 12 · **Tags** `network`  
**Constraint** `tag=network`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dns` | Rec | string | The domain name server for the resource. |
| `interface` | Rec | string | The network interfaces of the computing resource, such as eth0, eth1 or Wired Eth… |
| `ip` | Rec | string | The network addresses of the computing resource, such as 192.168.1.1 or E80:0000:… |
| `mac` | Rec | string | A MAC (media access control) address associated with the resource, such as 06:10:… |
| `name` | Rec | string | A name field provided in some data sources. |
| `dest_ip` | Opt | string | The IP address for the system that the data is going to. |
| `inline_nat` | Opt | string | Identifies whether the resource is a network address translation pool. |
| `lb_method` | Opt | string | The load balancing method used by the computing resource such as method, round ro… |
| `node` | Opt | string | Represents a node hit. |
| `node_port` | Opt | number | The number of the destination port on the server that you requested from. |
| `src_ip` | Opt | string | The IP address for the system from which the data originates. |
| `vip_port` | Opt | number | The port number for the virtual IP address (VIP). A VIP allows multiple MACs to u… |

### `All_Inventory.Storage`

**Object** `Storage` · **Parent** `All_Inventory` · **Fields** 14 · **Tags** `storage`  
**Constraint** `tag=storage`

| Field | St | Type | Description |
|---|:--:|---|---|
| `mount` | Rec | string | The path at which a storage resource is mounted. |
| `storage` | Rec | number | The amount of storage capacity allocated to the resource, in megabytes. |
| `array` | Opt | string | The array that the storage resource is a member of, if applicable. |
| `blocksize` | Opt | number | The block size used by the storage resource, in kilobytes. |
| `cluster` | Opt | string | The index cluster that the resource is a member of, if applicable. |
| `fd_max` | Opt | number | The maximum number of file descriptors available. |
| `latency` | Opt | number | The latency reported by the resource, in milliseconds. |
| `parent` | Opt | string | A higher level object that this resource is owned by, if applicable. |
| `read_blocks` | Opt | number | The maximum possible number of blocks read per second during a polling period. |
| `read_latency` | Opt | number | For a polling period, the average amount of time elapsed until a read request is… |
| `read_ops` | Opt | number | The total number of read operations in the polling period. |
| `write_blocks` | Opt | number | The maximum possible number of blocks written per second during a polling period. |
| `write_latency` | Opt | number | For a polling period, the average amount of time elapsed until a write request is… |
| `write_ops` | Opt | number | The total number of write operations in the polling period. |

### `All_Inventory.OS`

**Object** `OS` · **Parent** `All_Inventory` · **Fields** 1 · **Tags** `system`, `version`  
**Constraint** `tag=system tag=version`

| Field | St | Type | Description |
|---|:--:|---|---|
| `os` | Rec | string | The operating system of the resource, such as Microsoft Windows Server 2008r2. Th… (Eval) |

### `All_Inventory.User`

**Object** `User` · **Parent** `All_Inventory` · **Fields** 8 · **Tags** `user`  
**Constraint** `tag=user`

| Field | St | Type | Description |
|---|:--:|---|---|
| `interactive` | Rec | boolean | Indicates whether a locally defined account on a resource can be interactively lo… (Eval) |
| `password` | Rec | string | Displays the stored password(s) for a locally defined account, if it has any. For… (Eval) |
| `user` | Rec | string | The full name of a locally defined account. (Eval) |
| `shell` | Opt | string | Indicates the shell program used by a locally defined account. |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_id` | Opt | number | The user identification for a locally defined account. |
| `user_priority` | Opt | string | The priority of a locally-defined account. |

### `All_Inventory.Virtual_OS`

**Object** `Virtual_OS` · **Parent** `All_Inventory` · **Fields** 1 · **Tags** `virtual`  
**Constraint** `tag=virtual`

| Field | St | Type | Description |
|---|:--:|---|---|
| `hypervisor` | Rec | string | The hypervisor parent of a virtual guest OS. |

### `Virtual_OS.Snapshot`

**Object** `Snapshot` · **Parent** `Virtual_OS` · **Fields** 3 · **Tags** `snapshot`  
**Constraint** `tag=snapshot`

| Field | St | Type | Description |
|---|:--:|---|---|
| `size` | Rec | number | The snapshot file size, in megabytes. |
| `snapshot` | Rec | string | The name of a snapshot file. |
| `time` | Opt | timestamp | The time at which the snapshot was taken. |

---

## DLP

### `DLP_Incidents`

**Object** `DLP_Incidents` · **Parent** `BaseEvent` · **Fields** 37 · **Tags** `dlp`, `incident`  
**Constraint** ``(`cim_DLP_indexes`) tag=dlp tag=incident``

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | The action taken by the DLP device. (Eval) |
| `category` | Rec | string | The category of the DLP event. (Eval) |
| `dest` | Rec | string | The target of the DLP event. (Eval) |
| `dlp_type` | Rec | string | The type of DLP system that generated the event. (Eval) |
| `dvc` | Rec | string | The device that reported the DLP event. (Eval) |
| `object` | Rec | string | The name of the affected object. (Eval) |
| `object_category` | Rec | string | The category of the affected object. (Eval) |
| `object_path` | Rec | string | The path of the affected object. (Eval) |
| `severity` | Rec | string | The severity of the DLP event. (Eval) |
| `signature` | Rec | string | The name of the DLP event. (Eval) |
| `src` | Rec | string | The source of the DLP event. (Eval) |
| `src_user` | Rec | string | The source user of the DLP event. (Eval) |
| `user` | Rec | string | The target user of the DLP event. (Eval) |
| `vendor_product` | Rec | string | The vendor and product name of the DLP system. (Eval) |
| `app` | Opt | string | The application involved in the event. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_zone` | Opt | string | The zone of the DLP target. |
| `dvc_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc_zone` | Opt | string | The zone of the DLP device. |
| `severity_id` | Opt | string | The numeric or vendor specific severity indicator corresponding to the event seve… |
| `signature_id` | Opt | string | The unique identifier or event code of the event signature. |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_zone` | Opt | string | The zone of the DLP source. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

---

## Data_Access

### `Data_Access`

**Object** `Data_Access` · **Parent** `BaseEvent` · **Fields** 41 · **Tags** `data`, `access`  
**Constraint** ``(`cim_Data_Access_indexes`) tag=data tag=access``

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | The data access action taken by the user. (Eval) |
| `app` | Rec | string | The system, service, or application that generated the data access event. Example… (Eval) |
| `dest` | Rec | string | The destination where the data resides or where it is being accessed, such as the… (Eval) |
| `object` | Rec | string | Resource object name on which the action was performed by a user. (Eval) |
| `object_attrs` | Rec | string | The attributes that were updated on the updated resource object, if applicable. (Eval) |
| `object_category` | Rec | string | Generic name for the class of the updated resource object. Expected values may be… (Eval) |
| `object_id` | Rec | string | The unique updated resource object ID as presented to the system, if applicable… (Eval) |
| `object_size` | Rec | string | The size of the modified resource object. (Eval) |
| `signature` | Rec | string | A human-readable signature name. |
| `src` | Rec | string | The endpoint client host. (Eval) |
| `user` | Rec | string | The user involved in the event, or who initiated the event. (Eval) |
| `user_name` | Rec | string | The user name of the user or entity performing the change. For account changes, t… (Eval) |
| `vendor_account` | Rec | string | The account that manages the user that initiated the request. (Eval) |
| `vendor_product` | Rec | string | The vendor and product name of the vendor. (Eval) |
| `application_id` | Opt | string | Application ID of the user |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_name` | Opt | string | Name of the destination as defined by the Vendor. |
| `dest_type` | Opt | string | The type of the destination object, such as 'instance', 'storage', 'firewall', 'p… |
| `dest_url` | Opt | string | Url of the product, application or object. |
| `dvc` | Opt | string | The device that reported the data access event. |
| `dvc_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `email` | Opt | string | The email address of the user involved in the event, or who initiated the event. |
| `object_path` | Opt | string | The path of the modified resource object, if applicable, such as a file, director… |
| `owner` | Opt | string | Resource owner. |
| `owner_email` | Opt | string | Email of the resource owner. |
| `owner_id` | Opt | string | ID of the owner as defined by the vendor. |
| `parent_object` | Opt | string | Parent of the object name on which the action was performed by a user. |
| `parent_object_category` | Opt | string | Object category of the parent object on which action was performed by a user. |
| `parent_object_id` | Opt | string | Object id of the parent object on which the action was performed by a user. |
| `signature_id` | Opt | string | The unique identifier or event code of the event signature. |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_agent` | Opt | string | The user agent through which the request was made, such as Mozilla/5.0 (Macintosh… |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_email` | Opt | string | The email address of the user involved in the event, or who initiated the event. |
| `user_group` | Opt | string | The group of the user involved in the event, or who initiated the event. |
| `user_id` | Opt | string | The unique id of the user involved in the event. For authentication privilege esc… |
| `user_role` | Opt | string | The role of the user involved in the event, or who initiated the event. |
| `user_type` | Opt | string | The type of the user involved in the event or who initiated the event, such as IA… |
| `vendor_product_id` | Opt | string | The vendor and product name ID as defined by the vendor. |
| `vendor_region` | Opt | string | The data center region where the change occurred, such as us-west-2. |

**Prescribed values**  
`action` = accepted, commented, copied, created, deleted, disabled, downloaded, enabled, forwarded, granted, invited, locked, modified, moved, read, restarted, revoked, shared, started, stopped, uncommented, undeleted, unlocked, unshared, uploaded  
`object_category` = collaboration, file, folder, comment, task, note  

---

## Databases

### `All_Databases`

**Object** `All_Databases` · **Parent** `BaseEvent` · **Fields** 18 · **Tags** `database`  
**Constraint** ``(`cim_Databases_indexes`) tag=database``

| Field | St | Type | Description |
|---|:--:|---|---|
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest` | Opt | string | The destination of the database event. You can alias this from more specific fiel… |
| `dest_bunit` | Opt | string | The business unit of the destination. |
| `dest_category` | Opt | string | The category of the destination. |
| `dest_priority` | Opt | string | The priority of the destination. |
| `duration` | Opt | number | The amount of time for the completion of the database event, in seconds. |
| `object` | Opt | string | The name of the database object. |
| `response_time` | Opt | number | The amount of time it took to receive a response in the database event, in second… |
| `src` | Opt | string | The source of the database event. You can alias this from more specific fields, s… |
| `src_bunit` | Opt | string | The business unit of the source. |
| `src_category` | Opt | string | The category of the source. |
| `src_priority` | Opt | string | The priority of the source. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user` | Opt | string | Name of the database process user. |
| `user_bunit` | Opt | string | The business unit of the user. |
| `user_category` | Opt | string | The category associated with the user. |
| `user_priority` | Opt | string | The priority of the user. |
| `vendor_product` | Opt | string | The vendor and product name of the database system. This field can be automatical… (Eval) |

### `All_Databases.Database_Instance`

**Object** `Database_Instance` · **Parent** `All_Databases` · **Fields** 4 · **Tags** `instance`  
**Constraint** `tag=instance`

| Field | St | Type | Description |
|---|:--:|---|---|
| `instance_name` | Opt | string | The name of the database instance. |
| `instance_version` | Opt | string | The version of the database instance. |
| `process_limit` | Opt | number | The maximum number of processes that the database instance can handle. |
| `session_limit` | Opt | number | The maximum number of sessions that the database instance can handle. |

### `Database_Instance.Instance_Stats`

**Object** `Instance_Stats` · **Parent** `Database_Instance` · **Fields** 19 · **Tags** `stats`  
**Constraint** `tag=stats`

| Field | St | Type | Description |
|---|:--:|---|---|
| `availability` | Opt | string | The status of the database server. |
| `avg_executions` | Opt | number | The average number of executions for the database instance. |
| `dump_area_used` | Opt | string | The amount of the database dump area that has been used. |
| `instance_reads` | Opt | number | The total number of reads for the database instance. |
| `instance_writes` | Opt | number | The total number of writes for the database instance. |
| `number_of_users` | Opt | number | The total number of users for the database instance. |
| `processes` | Opt | number | The number of processes currently running for the database instance. |
| `sessions` | Opt | number | The total number of sessions currently in use for the database instance. |
| `sga_buffer_cache_size` | Opt | number | The total size of the buffer cache for the database instance, in bytes. |
| `sga_buffer_hit_limit` | Opt | number | The maximum number of buffers that can be hit in the database instance without fi… |
| `sga_data_dict_hit_ratio` | Opt | number | The hit-to-miss ratio for the database instance's data dictionary. |
| `sga_fixed_area_size` | Opt | number | The size of the fixed area (also referred to as the fixed SGA) for the database i… |
| `sga_free_memory` | Opt | number | The total amount of free memory in the database instance SGA, in bytes. |
| `sga_library_cache_size` | Opt | number | The total library cache size for the database instance, in bytes. |
| `sga_redo_log_buffer_size` | Opt | number | The total size of the redo log buffer for the database instance, in bytes. |
| `sga_shared_pool_size` | Opt | number | The total size of the shared pool for this database instance, in bytes. |
| `sga_sql_area_size` | Opt | number | The total size of the SQL area for this database instance, in bytes. |
| `start_time` | Opt | timestamp | The total amount of uptime for the database instance. |
| `tablespace_used` | Opt | string | The total amount of tablespace used for the database instance, in bytes. |

**Prescribed values**  
`availability` = Available, Not Available  

### `Database_Instance.Session_Info`

**Object** `Session_Info` · **Parent** `Database_Instance` · **Fields** 15 · **Tags** `session`  
**Constraint** `tag=session`

| Field | St | Type | Description |
|---|:--:|---|---|
| `buffer_cache_hit_ratio` | Opt | number | The percentage of logical reads from the buffer during the session (1-physical re… |
| `commits` | Opt | number | The number of commits per second performed by the user associated with the sessio… |
| `cpu_used` | Opt | number | The number of CPU centiseconds used by the session. Divide this value by 100 to g… |
| `cursor` | Opt | number | The number of the cursor currently in use by the session. |
| `elapsed_time` | Opt | number | The total amount of time elapsed since the user started the session by logging in… |
| `logical_reads` | Opt | number | The total number of consistent gets and database block gets performed during the… |
| `machine` | Opt | string | The name of the logical host associated with the database instance. |
| `memory_sorts` | Opt | number | The total number of memory sorts performed during the session. |
| `physical_reads` | Opt | number | The total number of physical reads performed during the session. |
| `seconds_in_wait` | Opt | number | The seconds_in_wait depends on the value of wait_time. If wait_time = 0, seconds_… |
| `session_id` | Opt | string | The unique id that identifies the session. |
| `session_status` | Opt | string | The current status of the session. |
| `table_scans` | Opt | number | Number of table scans performed during the session. |
| `wait_state` | Opt | string | Provides the current wait state for the session. Can indicate that the session is… |
| `wait_time` | Opt | number | When wait_time = 0, the session is waiting. When wait_time has a nonzero value, i… |

**Prescribed values**  
`session_status` = Online, Offline  
`wait_state` = WAITING, WAITED UNKNOWN, WAITED SHORT TIME, WAITED KNOWN TIME  

### `Database_Instance.Lock_Info`

**Object** `Lock_Info` · **Parent** `Database_Instance` · **Fields** 7 · **Tags** `lock`  
**Constraint** `tag=lock`

| Field | St | Type | Description |
|---|:--:|---|---|
| `last_call_minute` | Opt | number | Represents the amount of time elapsed since the session_status changed to its cur… |
| `lock_mode` | Opt | string | The mode of the lock on the object. |
| `lock_session_id` | Opt | string | The session identifier of the locked object. |
| `logon_time` | Opt | number | The database logon time for the session. |
| `obj_name` | Opt | string | The name of the locked object. |
| `os_pid` | Opt | string | The process identifier for the operating system. |
| `serial_num` | Opt | string | The serial number of the object. |

### `All_Databases.Database_Query`

**Object** `Database_Query` · **Parent** `All_Databases` · **Fields** 4 · **Tags** `query`  
**Constraint** `tag=query`

| Field | St | Type | Description |
|---|:--:|---|---|
| `query` | Opt | string | The full database query. |
| `query_id` | Opt | string | The identifier for the database query. |
| `query_time` | Opt | timestamp | The time the system initiated the database query. |
| `records_affected` | Opt | number | The number of records affected by the database query. |

### `Database_Query.Tablespace`

**Object** `Tablespace` · **Parent** `Database_Query` · **Fields** 5 · **Tags** `tablespace`  
**Constraint** `tag=tablespace`

| Field | St | Type | Description |
|---|:--:|---|---|
| `free_bytes` | Opt | number | The total amount of free space in the tablespace, in bytes. |
| `tablespace_name` | Opt | string | The name of the tablespace. |
| `tablespace_reads` | Opt | number | The number of tablespace reads carried out by the query. |
| `tablespace_status` | Opt | string | The status of the tablespace. |
| `tablespace_writes` | Opt | number | The number of tablespace writes carried out by the query. |

**Prescribed values**  
`tablespace_status` = Offline, Online, Read Only  

### `Database_Query.Query_Stats`

**Object** `Query_Stats` · **Parent** `Database_Query` · **Fields** 4 · **Tags** `stats`  
**Constraint** `tag=stats`

| Field | St | Type | Description |
|---|:--:|---|---|
| `indexes_hit` | Opt | string | The names of the indexes hit by the database query. |
| `query_plan_hit` | Opt | string | The name of the query plan hit by the query. |
| `stored_procedures_called` | Opt | string | The names of the stored procedures called by the query. |
| `tables_hit` | Opt | string | The names of the tables hit by the query. |

---

## Email

### `All_Email`

**Object** `All_Email` · **Parent** `BaseEvent` · **Fields** 48 · **Tags** `email`  
**Constraint** ``(`cim_Email_indexes`) tag=email``

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | Action taken by the reporting device. (Eval) |
| `dest` | Rec | string | The endpoint system to which the message was delivered. You can alias this from m… (Eval) |
| `recipient` | Rec | string | The recipient email addresses. (Eval) |
| `recipient_domain` | Rec | string | The domain name contained within the recipient email addresses. (Rex) |
| `src` | Rec | string | The system that sent the message. You can alias this from more specific fields, s… (Eval) |
| `src_user` | Rec | string | The email address of the message sender. (Eval) |
| `src_user_domain` | Rec | string | The domain name contained within the email address of the message sender. (Rex) |
| `vendor_product` | Rec | string | The vendor and product of the email server used for the email transaction. This f… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `delay` | Opt | number | Total sending delay in milliseconds. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `duration` | Opt | number | The amount of time for the completion of the messaging event, in seconds. |
| `file_hash` | Opt | string | The hashes for the files attached to the message, if any exist. |
| `file_name` | Opt | string | The names of the files attached to the message, if any exist. |
| `file_size` | Opt | number | The size of the files attached the message, in bytes. |
| `internal_message_id` | Opt | string | Host-specific unique message identifier (such as aid in sendmail, IMI in Domino… |
| `message_id` | Opt | string | The globally-unique message identifier. |
| `message_info` | Opt | string | Additional information about the message. |
| `orig_dest` | Opt | string | The original destination host of the message. The message destination host can ch… |
| `orig_recipient` | Opt | string | The original recipient of the message. The message recipient can change when the… |
| `orig_src` | Opt | string | The original source of the message. |
| `process` | Opt | string | The name of the email executable that carries out the message transaction, such a… |
| `process_id` | Opt | number | The numeric identifier of the process invoked to send the message. |
| `protocol` | Opt | string | The email protocol involved, such as SMTP or RPC. |
| `recipient_count` | Opt | number | The total number of intended message recipients. (Eval) |
| `recipient_status` | Opt | string | The recipient delivery status, if available. |
| `response_time` | Opt | number | The amount of time it took to receive a response in the messaging event, in secon… |
| `retries` | Opt | number | The number of times that the message was automatically resent because it was boun… |
| `return_addr` | Opt | string | The return address for the message. |
| `size` | Opt | number | The size of the message, in bytes. |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `status_code` | Opt | string | The status code associated with the message. |
| `subject` | Opt | string | The subject of the message. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `url` | Opt | string | The URL associated with the message, if any. |
| `user` | Opt | string | The user context for the process. This is not the email address for the sender. F… |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `xdelay` | Opt | string | Extended delay information for the message transaction. May contain details of al… |
| `xref` | Opt | string | An external reference. Can contain message IDs or recipient addresses from relate… |

**Prescribed values**  
`action` = delivered, blocked, quarantined, deleted  
`protocol` = smtp, imap, pop3, mapi  

### `All_Email.Filtering`

**Object** `Filtering` · **Parent** `All_Email` · **Fields** 5 · **Tags** `filter`  
**Constraint** `tag=filter`

| Field | St | Type | Description |
|---|:--:|---|---|
| `signature` | Rec | string | The name of the filter applied. |
| `filter_action` | Opt | string | The status produced by the filter, such as 'accepted', 'rejected', or 'dropped'. |
| `filter_score` | Opt | number | Numeric indicator assigned to specific emails by an email filter. |
| `signature_extra` | Opt | string | Any additional information about the filter. |
| `signature_id` | Opt | string | The id associated with the filter name. |

---

## Endpoint

### `Ports`

**Object** `Ports` · **Parent** `BaseSearch` · **Fields** 29  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Rec | string | The endpoint for which the port is listening on. (Eval) |
| `dest_port` | Rec | number | Network port listening on the endpoint, such as 53. |
| `src` | Rec | string | The "remote" system connected to the listening port (if applicable). (Eval) |
| `src_port` | Rec | number | The "remote" port connected to the listening port (if applicable). (Eval) |
| `transport` | Rec | string | The network transport protocol associated with the listening port, such as tcp, u… |
| `user` | Rec | string | The user account associated with the listening port. (Eval) |
| `vendor_product` | Rec | string | The vendor and product name of the Endpoint solution that reported the event, suc… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `creation_time` | Opt | timestamp | The time at which the network port started listening on the endpoint. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_requires_av` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_timesync` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_update` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `process_guid` | Opt | string | The globally unique identifier of the process assigned by the vendor_product. |
| `process_id` | Opt | string | The numeric identifier of the process assigned by the operating system. |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_requires_av` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `src_should_timesync` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `src_should_update` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `state` | Opt | string | The status of the listening port, such as established, listening, etc. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `transport_dest_port` | Opt | string | Calculated as transport/dest_port, such as tcp/53. |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

### `Processes`

**Object** `Processes` · **Parent** `BaseSearch` · **Fields** 39  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Rec | string | The endpoint for which the process was spawned. (Eval) |
| `loaded_file` | Rec | string | The file that was loaded. (Eval) |
| `original_file_name` | Rec | string | Original name of the file, not including path. Sometimes this field is similar to… (Eval) |
| `parent_process` | Rec | string | The full command string of the parent process (Eval) |
| `parent_process_name` | Rec | string | The friendly name of the parent process, such as notepad.exe. (Eval) |
| `process` | Rec | string | The full command string of the spawned process. Such as C:\WINDOWS\system32\cmd.e… (Eval) |
| `process_name` | Rec | string | The friendly name of the process, such as notepad.exe. (Eval) |
| `user` | Rec | string | The current user linked to the running process. (Eval) |
| `vendor_product` | Rec | string | The vendor and product name of the Endpoint solution that reported the event, suc… (Eval) |
| `action` | Opt | string | The action taken by the endpoint. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `cpu_load_percent` | Opt | number | CPU load consumed by the process (in percent). |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_is_expected` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_requires_av` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_timesync` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_update` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `mem_used` | Opt | number | Memory used by the process (in bytes). |
| `os` | Opt | string | The operating system of the resource, such as Microsoft Windows Server 2008r2. |
| `parent_process_exec` | Opt | string | The executable name of the parent process. |
| `parent_process_guid` | Opt | string | The globally unique identifier of the parent process assigned by the vendor_produ… |
| `parent_process_hash` | Opt | string | The digest(s) of the parent process, such as <md5>, <sha1>, etc. |
| `parent_process_id` | Opt | number | The numeric identifier of the parent process assigned by the operating system. |
| `parent_process_path` | Opt | string | The file path of the parent process, such as C:\Windows\System32\notepad.exe. |
| `parent_user` | Opt | string | The original user under which the process was created. This field is extracted fo… (Eval) |
| `process_current_directory` | Opt | string | The current working directory used to spawn the process. |
| `process_exec` | Opt | string | The executable name of the process. |
| `process_guid` | Opt | string | The globally unique identifier of the process assigned by the vendor_product. |
| `process_hash` | Opt | string | The digest(s) of the process, such as <md5>, <sha1>, etc. |
| `process_id` | Opt | number | The numeric identifier of the process assigned by the operating system. |
| `process_integrity_level` | Opt | string | The integrity level of the process. |
| `process_path` | Opt | string | The file path of the process, such as C:\Windows\System32\notepad.exe. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_id` | Opt | string | The unique identifier of the user account which spawned the process. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

**Prescribed values**  
`process_integrity_level` = protected process, system, high, medium high, medium, low, untrusted  

### `Services`

**Object** `Services` · **Parent** `BaseSearch` · **Fields** 33  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Rec | string | The endpoint for which the service is installed. (Eval) |
| `service` | Rec | string | The full service name. (Eval) |
| `service_id` | Rec | string | The unique identifier of the service assigned by the operating system.. (Eval) |
| `service_name` | Rec | string | The friendly service name. (Eval) |
| `start_mode` | Rec | string | The start mode for the service. (Eval) |
| `status` | Rec | string | The status of the service. (Eval) |
| `user` | Rec | string | The user account associated with the service. (Eval) |
| `vendor_product` | Rec | string | The vendor and product name of the Endpoint solution that reported the event, suc… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `description` | Opt | string | The description of the service. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_is_expected` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_requires_av` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_timesync` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_update` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `process_guid` | Opt | string | The globally unique identifier of the process assigned by the vendor_product. |
| `process_id` | Opt | string | The numeric identifier of the process assigned by the operating system. |
| `service_dll` | Opt | string | The dynamic link library associated with the service. |
| `service_dll_hash` | Opt | string | The digest(s) of the dynamic link library associated with the service, such as <m… |
| `service_dll_path` | Opt | string | The file path to the dynamic link library assocatied with the service, such as C:… |
| `service_dll_signature_exists` | Opt | boolean | Whether or not the dynamic link library associated with the service has a digital… |
| `service_dll_signature_verified` | Opt | boolean | Whether or not the dynamic link library associated with the service has had it's… |
| `service_exec` | Opt | string | The executable name of the service. |
| `service_hash` | Opt | string | The digest(s) of the service, such as <md5>, <sha1>, etc. |
| `service_path` | Opt | string | The file path of the service, such as C:\WINDOWS\system32\svchost.exe. |
| `service_signature_exists` | Opt | boolean | Whether or not the service has a digitally signed signature. |
| `service_signature_verified` | Opt | boolean | Whether or not the service has had it's digitally signed signature verified. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

**Prescribed values**  
`start_mode` = disabled, manual, auto  
`status` = critical, started, stopped, warning, installed  

### `Filesystem`

**Object** `Filesystem` · **Parent** `BaseSearch` · **Fields** 38  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | The action performed on the resource. (Eval) |
| `dest` | Rec | string | The endpoint pertaining to the filesystem activity. (Eval) |
| `file_access_time` | Rec | timestamp | The time the file (the object of the event) was accessed. |
| `file_acl` | Rec | string | Access controls associated with the file affected by the event. (Eval) |
| `file_create_time` | Rec | timestamp | The time the file (the object of the event) was created. |
| `file_hash` | Rec | string | A cryptographic identifier assigned to the file object affected by the event. (Eval) |
| `file_modify_time` | Rec | timestamp | The time the file (the object of the event) was altered. |
| `file_name` | Rec | string | The name of the file, such as notepad.exe. (Eval) |
| `file_path` | Rec | string | The path of the file, such as C:\Windows\System32\notepad.exe. (Eval) |
| `file_size` | Rec | number | The size of the file that is the object of the event, in kilobytes. (Eval) |
| `process` | Rec | string | The full command string of the spawned process. Such as C:\WINDOWS\system32\cmd.e… (Eval) |
| `process_name` | Rec | string | The friendly name of the process, such as notepad.exe. (Eval) |
| `user` | Rec | string | The user account associated with the filesystem access. (Eval) |
| `vendor_product` | Rec | string | The vendor and product name of the Endpoint solution that reported the event, suc… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_requires_av` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_timesync` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_update` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `image` | Opt | string | The binary file path or name that is tied to a process ID (PID) in events like pr… |
| `parent_process` | Opt | string | The full command string of the parent process (Eval) |
| `parent_process_exec` | Opt | string | The executable name of the parent process. |
| `parent_process_guid` | Opt | string | The globally unique identifier of the parent process assigned by the vendor_produ… |
| `parent_process_hash` | Opt | string | The digest(s) of the parent process, such as <md5>, <sha1>, etc. |
| `parent_process_id` | Opt | number | The numeric identifier of the parent process assigned by the operating system. |
| `parent_process_name` | Opt | string | The friendly name of the parent process, such as notepad.exe. (Eval) |
| `parent_process_path` | Opt | string | The file path of the parent process, such as C:\Windows\System32\notepad.exe. |
| `process_exec` | Opt | string | The executable name of the process. |
| `process_guid` | Opt | string | The globally unique identifier of the process assigned by the vendor_product. |
| `process_hash` | Opt | string | The digest(s) of the process, such as <md5>, <sha1>, etc. |
| `process_id` | Opt | string | The numeric identifier of the process assigned by the operating system. |
| `process_path` | Opt | string | The file path of the process, such as C:\Windows\System32\notepad.exe. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

**Prescribed values**  
`action` = acl_modified, created, deleted, modified, read  

### `Registry`

**Object** `Registry` · **Parent** `BaseSearch` · **Fields** 38  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | The action performed on the resource. (Eval) |
| `dest` | Rec | string | The endpoint pertaining to the registry events. (Eval) |
| `process` | Rec | string | The full command string of the spawned process. Such as C:\WINDOWS\system32\cmd.e… (Eval) |
| `process_name` | Rec | string | The friendly name of the process, such as notepad.exe. (Eval) |
| `registry_key_name` | Rec | string | The name of the registry key, such as PrinterDriverData. (Eval) |
| `registry_path` | Rec | string | The path to the registry value, such as \win\directory\directory2\{676235CD-B656-… (Eval) |
| `registry_value_data` | Rec | string | The unaltered registry value. (Eval) |
| `registry_value_name` | Rec | string | The name of the registry value. (Eval) |
| `registry_value_type` | Rec | string | The type of the registry value. (Eval) |
| `user` | Rec | string | The user account associated with the registry access. (Eval) |
| `vendor_product` | Rec | string | The vendor and product name of the Endpoint solution that reported the event, suc… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_requires_av` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_timesync` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_update` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `image` | Opt | string | The binary file path or name that is tied to a process ID (PID) in events like pr… |
| `parent_process` | Opt | string | The full command string of the parent process (Eval) |
| `parent_process_exec` | Opt | string | The executable name of the parent process. |
| `parent_process_guid` | Opt | string | The globally unique identifier of the parent process assigned by the vendor_produ… |
| `parent_process_hash` | Opt | string | The digest(s) of the parent process, such as <md5>, <sha1>, etc. |
| `parent_process_id` | Opt | number | The numeric identifier of the parent process assigned by the operating system. |
| `parent_process_name` | Opt | string | The friendly name of the parent process, such as notepad.exe. (Eval) |
| `parent_process_path` | Opt | string | The file path of the parent process, such as C:\Windows\System32\notepad.exe. |
| `process_exec` | Opt | string | The executable name of the process. |
| `process_guid` | Opt | string | The globally unique identifier of the process assigned by the vendor_product. |
| `process_hash` | Opt | string | The digest(s) of the process, such as <md5>, <sha1>, etc. |
| `process_id` | Opt | string | The numeric identifier of the process assigned by the operating system. |
| `process_path` | Opt | string | The file path of the process, such as C:\Windows\System32\notepad.exe. |
| `registry_hive` | Opt | string | The logical grouping of registry keys, subkeys, and values. |
| `registry_value_text` | Opt | string | The textual representation of registry_value_data (if applicable). |
| `status` | Opt | string | The outcome of the registry action. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

**Prescribed values**  
`action` = created, deleted, modified, read  
`registry_value_type` = REG_BINARY, REG_DWORD, REG_DWORD_LITTLE_ENDIAN, REG_DWORD_BIG_ENDIAN, REG_EXPAND_SZ, REG_LINK, REG_MULTI_SZ, REG_NONE, REG_QWORD, REG_QWORD_LITTLE_ENDIAN, REG_SZ  
`registry_hive` = HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE\SAM, HKEY_LOCAL_MACHINE\Security, HKEY_LOCAL_MACHINE\Software, HKEY_LOCAL_MACHINE\System, HKEY_USERS\.DEFAULT  
`status` = failure, success  

---

## Event_Signatures

### `Signatures`

**Object** `Signatures` · **Parent** `BaseEvent` · **Fields** 9 · **Tags** `track_event_signatures`  
**Constraint** ``(`cim_Event_Signatures_indexes`) tag=track_event_signatures (signature=* OR signature_id=*)``

| Field | St | Type | Description |
|---|:--:|---|---|
| `vendor_product` | Rec | string | The vendor and product name of the technology that reported the event, such as Ca… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest` | Opt | string | System affected by the signature. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `signature` | Opt | string | The human readable event name. |
| `signature_id` | Opt | string | The event name identifier (as supplied by the vendor). |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |

---

## Interprocess_Messaging

### `All_Messaging`

**Object** `All_Messaging` · **Parent** `BaseEvent` · **Fields** 35 · **Tags** `messaging`  
**Constraint** ``(`cim_Interprocess_Messaging_indexes`) tag=messaging``

| Field | St | Type | Description |
|---|:--:|---|---|
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest` | Opt | string | The destination of the message. You can alias this from more specific fields, suc… (Eval) |
| `dest_bunit` | Opt | string | The business unit of the destination. |
| `dest_category` | Opt | string | The type of message destination. |
| `dest_priority` | Opt | string | The priority of the destination. |
| `duration` | Opt | number | The number of seconds from message call to message response. Can be derived by ge… |
| `endpoint` | Opt | string | The endpoint that the message accessed during the RPC (remote procedure call) tra… |
| `endpoint_version` | Opt | string | The version of the endpoint accessed during the RPC (remote procedure call) trans… |
| `message` | Opt | string | A command or reference that an RPC (remote procedure call) reads or responds to. |
| `message_consumed_time` | Opt | timestamp | The time that the RPC (remote procedure call) read the message and was prepared t… |
| `message_correlation_id` | Opt | string | The message correlation identification value. |
| `message_delivered_time` | Opt | timestamp | The time that the message producer sent the message. |
| `message_delivery_mode` | Opt | string | The message delivery mode. Possible values depend on the type of message-oriented… |
| `message_expiration_time` | Opt | timestamp | The time that the message expired. |
| `message_id` | Opt | string | The message identification. |
| `message_priority` | Opt | string | The priority of the message. Important jobs that the message queue should answer… |
| `message_properties` | Opt | string | An arbitrary list of message properties. The set of properties displayed depends… |
| `message_received_time` | Opt | timestamp | The time that the message was received by a message-oriented middleware (MOM) sol… |
| `message_redelivered` | Opt | boolean | Indicates whether or not the message was redelivered. |
| `message_reply_dest` | Opt | string | The name of the destination for replies to the message. |
| `message_type` | Opt | string | The type of message, such as call or reply. |
| `parameters` | Opt | string | Arguments that have been passed to an endpoint by a REST call or something simila… |
| `payload` | Opt | string | The message payload. |
| `payload_type` | Opt | string | The type of payload in the message. The payload type can be text (such as json, x… |
| `request_payload` | Opt | string | The content of the message request. |
| `request_payload_type` | Opt | string | The type of payload in the message request. The payload type can be text (such as… |
| `request_sent_time` | Opt | timestamp | The time that the message request was sent. |
| `response_code` | Opt | string | The response status code sent by the receiving server. Ranges between 200 and 404. |
| `response_payload_type` | Opt | string | The type of payload in the message response. The payload type can be text (such a… |
| `response_received_time` | Opt | timestamp | The time that the message response was received. |
| `response_time` | Opt | number | The amount of time it took to receive a response, in seconds. |
| `return_message` | Opt | string | The response status message sent by the message server. |
| `rpc_protocol` | Opt | string | The protocol that the message server uses for remote procedure calls (RPC). Possi… |
| `status` | Opt | boolean | The status of the message response. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |

**Prescribed values**  
`dest_category` = queue, topic  
`status` = pass, fail  

---

## Intrusion_Detection

### `IDS_Attacks`

**Object** `IDS_Attacks` · **Parent** `BaseEvent` · **Fields** 35 · **Tags** `ids`, `attack`  
**Constraint** ``(`cim_Intrusion_Detection_indexes`) tag=ids tag=attack``

| Field | St | Type | Description |
|---|:--:|---|---|
| `category` | Rec | string | The vendor-provided category of the triggered signature, such as spyware. Note: T… (Eval) |
| `dest` | Rec | string | The destination of the attack detected by the intrusion detection system (IDS). Y… (Eval) |
| `dvc` | Rec | string | The device that detected the intrusion event. You can alias this from more specif… (Eval) |
| `ids_type` | Rec | string | The type of IDS that generated the event. (Eval) |
| `severity` | Rec | string | The severity of the network protection event. Note: This field is a string. Use s… (Eval) |
| `signature` | Rec | string | The name of the intrusion detected on the client (the src), such as PlugAndPlay_B… (Eval) |
| `src` | Rec | string | The source involved in the attack detected by the IDS. You can alias this from mo… (Eval) |
| `user` | Rec | string | The user involved with the intrusion detection event. (Eval) |
| `vendor_product` | Rec | string | The vendor and product name of the IDS or IPS system that detected the vulnerabil… (Eval) |
| `action` | Opt | string | The action taken by the intrusion detection system (IDS). |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_ip` | Opt | string | The IP address of the destination. |
| `dest_port` | Opt | number | The destination port of the intrusion. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_type` | Opt | string | The type of the destination object, such as 'instance', 'storage', 'firewall'. |
| `dvc_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `file_hash` | Opt | string | A cryptographic identifier assigned to the file object affected by the event. |
| `file_name` | Opt | string | The name of the file, such as notepad.exe. |
| `file_path` | Opt | string | The path of the file, such as C:\Windows\System32\notepad.exe. |
| `severity_id` | Opt | string | The numeric or vendor specific severity indicator corresponding to the event seve… |
| `signature_id` | Opt | string | The unique identifier or event code of the event signature. |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_ip` | Opt | string | The ip address of the source. |
| `src_port` | Opt | number | The port number of the source. |
| `src_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `transport` | Opt | string | The OSI layer 4 (transport) protocol of the intrusion, in lower case. |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

**Prescribed values**  
`ids_type` = network, host, application, wireless  
`severity` = critical, high, medium, low, informational  
`action` = allowed, blocked  

---

## JVM

### `JVM`

**Object** `JVM` · **Parent** `BaseEvent` · **Fields** 3 · **Tags** `jvm`  
**Constraint** ``(`cim_JVM_indexes`) tag=jvm``

| Field | St | Type | Description |
|---|:--:|---|---|
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `jvm_description` | Opt | string | A description field provided in some data sources. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |

### `JVM.Threading`

**Object** `Threading` · **Parent** `JVM` · **Fields** 12 · **Tags** `threading`  
**Constraint** `tag=threading`

| Field | St | Type | Description |
|---|:--:|---|---|
| `cm_enabled` | Opt | boolean | Indicates whether thread contention monitoring is enabled. |
| `cm_supported` | Opt | boolean | Indicates whether the JVM supports thread contention monitoring. |
| `cpu_time_enabled` | Opt | boolean | Indicates whether thread CPU time measurement is enabled. |
| `cpu_time_supported` | Opt | boolean | Indicates whether the Java virtual machine supports CPU time measurement for the… |
| `current_cpu_time` | Opt | number | CPU-space time taken by the JVM, in seconds. |
| `current_user_time` | Opt | number | User-space time taken by the JVM, in seconds. |
| `daemon_thread_count` | Opt | number | The JVM's current daemon count. |
| `omu_supported` | Opt | boolean | Indicates whether the JVM supports monitoring of object monitor usage. |
| `peak_thread_count` | Opt | number | The JVM's peak thread count. |
| `synch_supported` | Opt | boolean | Indicates whether the JVM supports monitoring of ownable synchronizer usage. |
| `thread_count` | Opt | number | The JVM's current thread count. |
| `threads_started` | Opt | number | The total number of threads started in the JVM. |

**Prescribed values**  
`cm_enabled` = true, false, 1, 0  
`cm_supported` = true, false, 1, 0  
`cpu_time_enabled` = true, false, 1, 0  
`cpu_time_supported` = true, false, 1, 0  
`omu_supported` = true, false, 1, 0  
`synch_supported` = true, false, 1, 0  

### `JVM.Runtime`

**Object** `Runtime` · **Parent** `JVM` · **Fields** 5 · **Tags** `runtime`  
**Constraint** `tag=runtime`

| Field | St | Type | Description |
|---|:--:|---|---|
| `process_name` | Opt | string | Process name of the JVM process. |
| `start_time` | Opt | timestamp | Start time of the JVM process. |
| `uptime` | Opt | number | Uptime of the JVM process, in seconds. |
| `vendor_product` | Opt | string | The JVM product or service. This field can be automatically populated by the the… (Eval) |
| `version` | Opt | string | Version of the JVM. |

### `JVM.OS`

**Object** `OS` · **Parent** `JVM` · **Fields** 13 · **Tags** `os`  
**Constraint** `tag=os`

| Field | St | Type | Description |
|---|:--:|---|---|
| `committed_memory` | Opt | number | Amount of memory committed to the JVM, in bytes. |
| `cpu_time` | Opt | number | Amount of CPU time taken by the JVM, in seconds. |
| `free_physical_memory` | Opt | number | Amount of free physical memory remaining to the JVM, in bytes. |
| `free_swap` | Opt | number | Amount of free swap memory remaining to the JVM, in bytes. |
| `max_file_descriptors` | Opt | number | Maximum file descriptors available to the JVM. |
| `open_file_descriptors` | Opt | number | Number of file descriptors opened by the JVM. |
| `os` | Opt | string | OS that the JVM is running on. |
| `os_architecture` | Opt | string | OS architecture that the JVM is running on. |
| `os_version` | Opt | string | OS version that the JVM is running on. |
| `physical_memory` | Opt | number | Physical memory available to the OS that the JVM is running on, in bytes. |
| `swap_space` | Opt | number | Swap memory space available to the OS that the JVM is running on, in bytes. |
| `system_load` | Opt | number | System load of the OS that the JVM is running on. |
| `total_processors` | Opt | number | Total processor cores available to the OS that the JVM is running on. |

### `JVM.Compilation`

**Object** `Compilation` · **Parent** `JVM` · **Fields** 1 · **Tags** `compilation`  
**Constraint** `tag=compilation`

| Field | St | Type | Description |
|---|:--:|---|---|
| `compilation_time` | Opt | number | Time taken by JIT compilation, in seconds. |

### `JVM.Classloading`

**Object** `Classloading` · **Parent** `JVM` · **Fields** 3 · **Tags** `classloading`  
**Constraint** `tag=classloading`

| Field | St | Type | Description |
|---|:--:|---|---|
| `current_loaded` | Opt | number | The current count of classes loaded in the JVM. |
| `total_loaded` | Opt | number | The total count of classes loaded in the JVM. |
| `total_unloaded` | Opt | number | The total count of classes unloaded from the JVM. |

### `JVM.Memory`

**Object** `Memory` · **Parent** `JVM` · **Fields** 9 · **Tags** `memory`  
**Constraint** `tag=memory`

| Field | St | Type | Description |
|---|:--:|---|---|
| `heap_committed` | Opt | number | Committed amount of heap memory used by the JVM, in bytes. |
| `heap_initial` | Opt | number | Initial amount of heap memory used by the JVM, in bytes. |
| `heap_max` | Opt | number | Maximum amount of heap memory used by the JVM, in bytes. |
| `heap_used` | Opt | number | Heap memory used by the JVM, in bytes. |
| `non_heap_committed` | Opt | number | Committed amount of non-heap memory used by the JVM, in bytes. |
| `non_heap_initial` | Opt | number | Initial amount of non-heap memory used by the JVM, in bytes. |
| `non_heap_max` | Opt | number | Maximum amount of non-heap memory used by the JVM, in bytes. |
| `non_heap_used` | Opt | number | Non-heap memory used by the JVM, in bytes. |
| `objects_pending` | Opt | number | Number of objects pending in the JVM. |

---

## Malware

### `Malware_Attacks`

**Object** `Malware_Attacks` · **Parent** `BaseEvent` · **Fields** 31 · **Tags** `malware`, `attack`  
**Constraint** ``(`cim_Malware_indexes`) tag=malware tag=attack``

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | The action taken by the reporting device. (Eval) |
| `category` | Rec | string | The category of the malware event, such as keylogger or ad-supported program. Not… (Eval) |
| `date` | Rec | string | The date of the malware event. (Eval) |
| `dest` | Rec | string | The system that was affected by the malware event. You can alias this from more s… (Eval) |
| `dest_nt_domain` | Rec | string | The NT domain of the destination, if applicable. (Eval) |
| `severity` | Rec | string | The severity of the network protection event. Note: This field is a string. Use s… (Eval) |
| `signature` | Rec | string | The name of the malware infection detected on the client (the dest), such as Troj… (Eval) |
| `user` | Rec | string | The user involved in the malware event. (Eval) |
| `vendor_product` | Rec | string | The vendor and product name of the endpoint protection system, such as Symantec A… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_ip` | Opt | string | The IP address of the destination. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_requires_av` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `file_hash` | Opt | string | The hash of the file with suspected malware. |
| `file_name` | Opt | string | The name of the file with suspected malware. |
| `file_path` | Opt | string | The full file path of the file with suspected malware. |
| `severity_id` | Opt | string | The numeric or vendor specific severity indicator corresponding to the event seve… |
| `signature_id` | Opt | string | The unique identifier or event code of the event signature. |
| `src` | Opt | string | The source of the endpoint event, such as a DAT file relay server. You can alias… |
| `src_bunit` | Opt | string | The business unit of the source. |
| `src_category` | Opt | string | The category of the source. |
| `src_ip` | Opt | string | The ip address of the source. |
| `src_priority` | Opt | string | The priority of the source. |
| `src_user` | Opt | string | The reported sender of an email-based attack. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `url` | Opt | string | A URL containing more information about the vulnerability. |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

**Prescribed values**  
`action` = allowed, blocked, deferred  
`severity` = critical, high, medium, low, informational  

### `Malware_Operations`

**Object** `Malware_Operations` · **Parent** `BaseSearch` · **Fields** 13  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Rec | string | The system where the malware operations event occurred. (Eval) |
| `dest_nt_domain` | Rec | string | The NT domain of the dest system, if applicable. (Eval) |
| `product_version` | Rec | string | The product version of the malware operations product. |
| `signature_version` | Rec | string | The version of the malware signature bundle in a signature update operations even… |
| `vendor_product` | Rec | string | The vendor product name of the malware operations product. (Eval) |
| `_time` | Opt | timestamp | The event timestamp expressed in Unix time. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_ip` | Opt | string | The IP address of the destination. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_requires_av` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |

---

## Network_Resolution

### `DNS`

**Object** `DNS` · **Parent** `BaseEvent` · **Fields** 32 · **Tags** `network`, `resolution`, `dns`  
**Constraint** ``(`cim_Network_Resolution_indexes`) tag=network tag=resolution tag=dns``

| Field | St | Type | Description |
|---|:--:|---|---|
| `answer` | Rec | string | Resolved address for the query. (Eval) |
| `dest` | Rec | string | The destination of the network resolution event. You can alias this from more spe… (Eval) |
| `message_type` | Rec | string | Type of DNS message. (Eval) |
| `query` | Rec | string | The domain which needs to be resolved. Applies to messages of type 'Query'. (Eval) |
| `reply_code` | Rec | string | The return code for the response. For details, see the Domain Name System Paramet… (Lookup) |
| `reply_code_id` | Rec | string | The numerical id or name of a return code. For details, see the Domain Name Syste… (Eval) |
| `vendor_product` | Rec | string | The vendor product name of the DNS server. The Splunk platform can derive this fi… (Eval) |
| `additional_answer_count` | Opt | number | Number of entries in the 'additional' section of the DNS message. |
| `answer_count` | Opt | number | Number of entries in the answer section of the DNS message. (Eval) |
| `authority_answer_count` | Opt | number | Number of entries in the 'authority' section of the DNS message. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | The business unit of the destination. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_ip` | Opt | string | The IP address of the destination. |
| `dest_port` | Opt | number | The destination port number. |
| `dest_priority` | Opt | string | The priority of the destination, if applicable. |
| `duration` | Opt | number | The time taken by the network resolution event, in seconds. |
| `name` | Opt | string | The name of the DNS event. |
| `query_count` | Opt | number | Number of entries that appear in the 'Questions' section of the DNS query. (Eval) |
| `query_type` | Opt | string | Number of entries that appear in the 'Questions' section of the DNS query. |
| `record_type` | Opt | string | The DNS resource record type. For details, see the List of DNS record types on on… |
| `response_time` | Opt | number | The amount of time it took to receive a response in the network resolution event… |
| `src` | Opt | string | The source of the network resolution event. You can alias this from more specific… |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_ip` | Opt | string | The ip address of the source. |
| `src_port` | Opt | number | The port number of the source. |
| `src_priority` | Opt | string | The priority of the source. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `transaction_id` | Opt | number | The unique numerical transaction id of the network resolution event. |
| `transport` | Opt | string | The transport protocol used by the network resolution event. |
| `ttl` | Opt | number | The time-to-live of the network resolution event, in seconds. |

**Prescribed values**  
`message_type` = Query, Response  
`reply_code` = No Error, Format Error, Server Failure, Non-Existent Domain, etc.  
`reply_code_id` = 0, NoError, 1, FormErr, 2, ServFail, 3, NXDomain, etc.  
`query_type` = Query, IQuery, Status, Notify, Update, A, MX, NS, PTR  

---

## Network_Sessions

### `All_Sessions`

**Object** `All_Sessions` · **Parent** `BaseEvent` · **Fields** 27 · **Tags** `network`, `session`  
**Constraint** ``(`cim_Network_Sessions_indexes`) tag=network tag=session``

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest_dns` | Rec | string | The domain name system address of the destination for a network session event. (Eval) |
| `dest_ip` | Rec | string | The internal IP address allocated to the client initializing a network session. F… (Eval) |
| `dest_mac` | Rec | string | The internal MAC address of the network session client. For DHCP events, this is… (Eval) |
| `dest_nt_host` | Rec | string | The NetBIOS name of the client initializing a network session. (Eval) |
| `dvc` | Rec | string | The device that reported the session event. You can alias this from more specific… (Eval) |
| `user` | Rec | string | The user in a network session event, where applicable. For example, a VPN session… (Eval) |
| `vendor_product` | Rec | string | The full name of the Dynamic Host Configuration Protocol (DHCP) or DNS server inv… (Eval) |
| `action` | Opt | string | The action taken by the reporting device. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | The business unit of the destination. |
| `dest_category` | Opt | string | The category of the destination. |
| `dest_priority` | Opt | string | The priority of the destination. |
| `duration` | Opt | number | The amount of time for the completion of the network session event, in seconds. |
| `response_time` | Opt | number | The amount of time it took to receive a response in the network session event, in… |
| `signature` | Opt | string | An indication of the type of network session event. |
| `signature_id` | Opt | string | The unique identifier or event code of the event signature. |
| `src_bunit` | Opt | string | The business unit of the source. |
| `src_category` | Opt | string | The category of the source. |
| `src_dns` | Opt | string | The external domain name of the client initializing a network session. Not applic… |
| `src_ip` | Opt | string | The IP address of the client initializing a network session. Not applicable for D… |
| `src_mac` | Opt | string | The MAC address of the client initializing a network session. Not applicable for… |
| `src_nt_host` | Opt | string | The NetBIOS name of the client initializing a network session. Not applicable for… |
| `src_priority` | Opt | string | The priority of the source. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `user_bunit` | Opt | string | The business unit associated with the user. |
| `user_category` | Opt | string | The category of the user. |
| `user_priority` | Opt | string | The priority of the user. |

**Prescribed values**  
`action` = started, blocked, ended  

### `All_Sessions.DHCP`

**Object** `DHCP` · **Parent** `All_Sessions` · **Fields** 2 · **Tags** `dhcp`  
**Constraint** `tag=dhcp`

| Field | St | Type | Description |
|---|:--:|---|---|
| `lease_duration` | Opt | number | The duration of the Dynamic Host Configuration Protocol (DHCP) lease, in seconds. |
| `lease_scope` | Opt | string | The consecutive range of possible IP addresses that the Dynamic Host Configuratio… |

---

## Network_Traffic

### `All_Traffic`

**Object** `All_Traffic` · **Parent** `BaseEvent` · **Fields** 66 · **Tags** `network`, `communicate`  
**Constraint** ``(`cim_Network_Traffic_indexes`) tag=network tag=communicate``

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | The action taken by the network device. (Eval) |
| `bytes` | Rec | number | Total count of bytes handled by this device/interface (bytes_in + bytes_out). (Eval) |
| `bytes_in` | Rec | number | How many bytes this device/interface received. (Eval) |
| `bytes_out` | Rec | number | How many bytes this device/interface transmitted. (Eval) |
| `dest` | Rec | string | The destination of the network traffic (the remote host). You can alias this from… (Eval) |
| `dest_port` | Rec | number | The destination port of the network traffic. Note: Do not translate the value of… (Eval) |
| `dvc` | Rec | string | The device that reported the traffic event. You can alias this from more specific… (Eval) |
| `rule` | Rec | string | The rule name that defines the action that was taken in the event. Note: Use rule… (Eval) |
| `src` | Rec | string | The source of the network traffic (the client requesting the connection). You can… (Eval) |
| `src_port` | Rec | string | The source port of the network traffic. Note: Do not translate the value of this… (Eval) |
| `transport` | Rec | string | The OSI layer 4 (transport) protocol of the traffic observed, in lower case. (Eval) |
| `user` | Rec | string | The user that requested the traffic flow. (Eval) |
| `vendor_product` | Rec | string | The vendor and product of the device generating the network event. This field can… (Eval) |
| `app` | Opt | string | The application protocol of the traffic. |
| `channel` | Opt | number | The 802.11 channel used by a wireless network. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_interface` | Opt | string | The interface that is listening remotely or receiving packets locally. Can also b… |
| `dest_ip` | Opt | string | The IP address of the destination. |
| `dest_mac` | Opt | string | The destination TCP/IP layer 2 Media Access Control (MAC) address of a packet's d… |
| `dest_priority` | Opt | string | The destination priority, if applicable. |
| `dest_translated_ip` | Opt | string | The NATed IPv4 or IPv6 address to which a packet has been sent. |
| `dest_translated_port` | Opt | number | The NATed port to which a packet has been sent. Note: Do not translate the values… |
| `dest_zone` | Opt | string | The network zone of the destination. |
| `direction` | Opt | string | The direction the packet is traveling. |
| `duration` | Opt | number | The amount of time for the completion of the network event, in seconds. |
| `dvc_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc_ip` | Opt | string | The ip address of the device. |
| `dvc_mac` | Opt | string | The device TCP/IP layer 2 Media Access Control (MAC) address of a packet's destin… |
| `dvc_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc_zone` | Opt | string | The network zone of the device. |
| `flow_id` | Opt | string | Unique identifier for this traffic stream, such as a netflow, jflow, or cflow. |
| `icmp_code` | Opt | string | The RFC 2780 or RFC 4443 human-readable code value of the traffic, such as Destin… |
| `icmp_type` | Opt | number | The RFC 2780 or RFC 4443 numeric value of the traffic. See the ICMP Type Numbers… |
| `packets` | Opt | number | The total count of packets handled by this device/interface (packets_in + packets… (Eval) |
| `packets_in` | Opt | number | The total count of packets received by this device/interface. (Eval) |
| `packets_out` | Opt | number | The total count of packets transmitted by this device/interface. (Eval) |
| `process_guid` | Opt | string | The globally unique identifier of the process assigned by the vendor_product. |
| `process_id` | Opt | string | The numeric identifier of the process assigned by the operating system. |
| `protocol` | Opt | string | The OSI layer 3 (network) protocol of the traffic observed, in lower case. For ex… |
| `protocol_version` | Opt | string | Version of the OSI layer 3 protocol, in lower case. |
| `response_time` | Opt | number | The amount of time it took to receive a response in the network event, in seconds. |
| `rule_id` | Opt | string | The vendor-specific unique identifier of the rule. Examples: 0x00011f0000011f00… |
| `session_id` | Opt | string | The session identifier. Multiple transactions build a session. |
| `src_bunit` | Opt | string | The business unit of the network traffic source. |
| `src_category` | Opt | string | The category of the network traffic source. |
| `src_interface` | Opt | string | The interface that is listening locally or sending packets remotely. Can also be… |
| `src_ip` | Opt | string | The ip address of the source. |
| `src_mac` | Opt | string | The source TCP/IP layer 2 Media Access Control (MAC) address of a packet's destin… |
| `src_priority` | Opt | string | The priority of the source, if applicable. |
| `src_translated_ip` | Opt | string | The NATed IPv4 or IPv6 address from which a packet has been sent. |
| `src_translated_port` | Opt | number | The NATed port from which a packet has been sent. Note: Do not translate the valu… |
| `src_zone` | Opt | string | The network zone of the source. |
| `ssid` | Opt | string | The 802.11 service set identifier (ssid) assigned to a wireless session. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `tcp_flag` | Opt | string | The TCP flag or multiple flags specified in the event. |
| `tos` | Opt | string | The combination of source and destination IP ToS (type of service) values in the… |
| `ttl` | Opt | number | The 'time to live' of a packet or diagram, in seconds. |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `vendor_account` | Opt | string | The account associated with the network traffic. |
| `vlan` | Opt | string | The virtual local area network (VLAN) specified in the record. |
| `wifi` | Opt | string | The wireless standard(s) in use, such as 802.11a, 802.11b, 802.11g, or 802.11n. |

**Prescribed values**  
`action` = allowed, blocked, teardown  
`transport` = tcp, udp, icmp  
`direction` = inbound, outbound  
`icmp_type` = 0-254  
`tcp_flag` = SYN, ACK, FIN, RST, URG, PSH  

---

## Performance

### `All_Performance`

**Object** `All_Performance` · **Parent** `BaseEvent` · **Fields** 10 · **Tags** `performance`, `cpu`, `facilities`, `memory`, `storage`, `network`, `os`, `time`, `synchronize`, `uptime`  
**Constraint** ``(`cim_Performance_indexes`) tag=performance (tag=cpu OR tag=facilities OR tag=memory OR tag=storage OR tag=network OR (tag=os ((tag=time tag=synchronize) OR tag=uptime)))``

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Rec | string | The system where the event occurred, usually a facilities resource such as a rack… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | The priority of the system where the performance event occurred. |
| `dest_should_timesync` | Opt | boolean | Indicates whether or not the system where the performance event occurred should t… |
| `dest_should_update` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `hypervisor_id` | Opt | string | The ID of the virtualization hypervisor. |
| `resource_type` | Opt | string | The type of facilities resource involved in the performance event, such as a rack… |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |

### `All_Performance.CPU`

**Object** `CPU` · **Parent** `All_Performance` · **Fields** 4 · **Tags** `cpu`  
**Constraint** `tag=cpu`

| Field | St | Type | Description |
|---|:--:|---|---|
| `cpu_load_percent` | Rec | number | The amount of CPU load reported by the controller in percentage points. |
| `cpu_load_mhz` | Opt | number | The amount of CPU load reported by the controller in megahertz. |
| `cpu_time` | Opt | number | The number of CPU seconds consumed by processes. |
| `cpu_user_percent` | Opt | number | Percentage of CPU user time consumed by processes. |

### `All_Performance.Facilities`

**Object** `Facilities` · **Parent** `All_Performance` · **Fields** 3 · **Tags** `facilities`  
**Constraint** `tag=facilities`

| Field | St | Type | Description |
|---|:--:|---|---|
| `temperature` | Rec | number | Average temperature of the facilities resource, in degrees Celsius. |
| `fan_speed` | Opt | number | The speed of the cooling fan in the facilities resource, in rotations per second. |
| `power` | Opt | number | Amount of power consumed by the facilities resource, in kW. |

### `All_Performance.Memory`

**Object** `Memory` · **Parent** `All_Performance` · **Fields** 7 · **Tags** `memory`  
**Constraint** `tag=memory`

| Field | St | Type | Description |
|---|:--:|---|---|
| `mem` | Rec | number | The total amount of memory capacity reported by the resource, in megabytes. |
| `mem_free` | Rec | number | The free amount of memory reported by the resource, in megabytes. |
| `mem_used` | Rec | number | The used amount of memory reported by the resource, in megabytes. |
| `mem_committed` | Opt | number | The committed amount of memory reported by the resource, in megabytes. |
| `swap` | Opt | number | The total swap space size, in megabytes, if applicable. |
| `swap_free` | Opt | number | The free swap space size, in megabytes, if applicable. |
| `swap_used` | Opt | number | The used swap space size, in megabytes, if applicable. |

### `All_Performance.Storage`

**Object** `Storage` · **Parent** `All_Performance` · **Fields** 19 · **Tags** `storage`  
**Constraint** `tag=storage`

| Field | St | Type | Description |
|---|:--:|---|---|
| `storage_free` | Rec | number | The free amount of storage capacity reported by the resource, in megabytes. |
| `storage_free_percent` | Rec | number | The percentage of storage capacity reported by the resource that is free. |
| `storage_used` | Rec | number | The used amount of storage capacity reported by the resource, in megabytes. |
| `storage_used_percent` | Rec | number | The percentage of storage capacity reported by the resource that is used. |
| `array` | Opt | string | The array that the resource is a member of, if applicable. |
| `blocksize` | Opt | number | Block size used by the storage resource, in kilobytes. |
| `cluster` | Opt | string | The cluster that the resource is a member of, if applicable. |
| `fd_max` | Opt | number | The maximum number of available file descriptors. |
| `fd_used` | Opt | number | The current number of open file descriptors. |
| `latency` | Opt | number | The latency reported by the resource, in milliseconds. |
| `mount` | Opt | string | The mount point of a storage resource. |
| `parent` | Opt | string | A generic indicator of hierarchy. For instance, a disk event might include the ar… |
| `read_blocks` | Opt | number | Number of blocks read. |
| `read_latency` | Opt | number | The latency of read operations, in milliseconds. |
| `read_ops` | Opt | number | Number of read operations. |
| `storage` | Opt | number | The total amount of storage capacity reported by the resource, in megabytes. |
| `write_blocks` | Opt | number | The number of blocks written by the resource. |
| `write_latency` | Opt | number | The latency of write operations, in milliseconds. |
| `write_ops` | Opt | number | The total number of write operations processed by the resource. |

### `All_Performance.Network`

**Object** `Network` · **Parent** `All_Performance` · **Fields** 2 · **Tags** `network`  
**Constraint** `tag=network`

| Field | St | Type | Description |
|---|:--:|---|---|
| `thruput` | Rec | string | The current throughput reported by the service, in bytes. |
| `thruput_max` | Opt | number | The maximum possible throughput reported by the service, in bytes. |

### `All_Performance.OS`

**Object** `OS` · **Parent** `All_Performance` · **Fields** 2 · **Tags** `os`  
**Constraint** `tag=os`

| Field | St | Type | Description |
|---|:--:|---|---|
| `signature` | Rec | string | The event description signature, if available. |
| `signature_id` | Opt | string | The unique identifier or event code of the event signature. |

### `OS.Timesync`

**Object** `Timesync` · **Parent** `OS` · **Fields** 1 · **Tags** `time`, `synchronize`  
**Constraint** `tag=time tag=synchronize`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | The result of a time sync event. (Eval) |

**Prescribed values**  
`action` = success, failure  

### `OS.Uptime`

**Object** `Uptime` · **Parent** `OS` · **Fields** 1 · **Tags** `uptime`  
**Constraint** `tag=uptime`

| Field | St | Type | Description |
|---|:--:|---|---|
| `uptime` | Rec | string | The uptime of the compute resource, in seconds. (Eval) |

---

## Splunk_Audit

> Internal Splunk audit/telemetry model — populated by Splunk; vendor add-ons normally do not map here.

### `Datamodel_Acceleration`

**Object** `Datamodel_Acceleration` · **Parent** `BaseSearch` · **Fields** 18  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `access_count` | Opt | number | The number of times the data model summary has been accessed since it was created. |
| `access_time` | Opt | timestamp | The timestamp of the most recent access of the data model summary. |
| `app` | Opt | string | The application context in which the data model summary was accessed. |
| `buckets` | Opt | number | The number of index buckets spanned by the data model acceleration summary. |
| `buckets_size` | Opt | number | The total size of the buckets spanned by the data model acceleration summary. |
| `complete` | Opt | number | The percentage of the data model summary that is currently complete. |
| `cron` | Opt | string | The cron expression used to accelerate the data model. |
| `datamodel` | Opt | string | The name of the data model accelerated. |
| `digest` | Opt | string | A hash of the current data model contents. |
| `earliest` | Opt | timestamp | The earliest time that the data model summary was accessed. |
| `is_inprogress` | Opt | boolean | Indicates whether the data model acceleration is currently in progress. |
| `last_error` | Opt | string | The text of the last error reported during the data model acceleration. |
| `last_sid` | Opt | string | The search id of the last acceleration attempt. |
| `latest` | Opt | timestamp | The most recent acceleration timestamp of the data model. |
| `mod_time` | Opt | timestamp | The timestamp of the most recent modification to the data model acceleration. |
| `retention` | Opt | number | The length of time that data model accelerations are retained, in seconds. |
| `size` | Opt | number | The amount of storage space the data model's acceleration summary takes up, in by… |
| `summary_id` | Opt | string | The unique id of the data model acceleration summary. |

**Prescribed values**  
`is_inprogress` = true, false, 1, 0  

### `Search_Activity`

**Object** `Search_Activity` · **Parent** `BaseEvent` · **Fields** 15  
**Constraint** `index=_audit action=search search_id=*`

| Field | St | Type | Description |
|---|:--:|---|---|
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `datamodel` | Opt | string | The name of the datamodel (for datamodel acceleration searches). (Eval) |
| `info` | Opt | string | The action of the search (granted, completed, cancelled, failed). |
| `savedsearch_name` | Opt | string | The name of the saved search. (Eval) |
| `search` | Opt | string | The SPL search syntax. (Eval) |
| `search_alias` | Opt | string | Short description of the type of search being run, such as the name of the search… (Eval) |
| `search_et` | Opt | string | The earliest time of the search. |
| `search_id` | Opt | string | The ID of the search. (Eval) |
| `search_lt` | Opt | string | The latest time of the search. |
| `search_type` | Opt | string | The type of search. (Eval) |
| `total_run_time` | Opt | string | The total run time of the search. |
| `user` | Opt | string | The name of the user who ran the search. (Rex) |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

### `Scheduler_Activity`

**Object** `Scheduler_Activity` · **Parent** `BaseSearch` · **Fields** 14  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | The event timestamp expressed in Unix time. |
| `app` | Opt | string | The app context in which the scheduled search was run. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `host` | Opt | string | The host on which the scheduled search was run. |
| `savedsearch_name` | Opt | string | The name of the saved search. |
| `sid` | Opt | string | The search id. |
| `source` | Opt | string | The source associated with the scheduled search. |
| `sourcetype` | Opt | string | The source type associated with the scheduled search. |
| `splunk_server` | Opt | string | The Splunk Server on which the scheduled search runs. |
| `status` | Opt | string | The status of the scheduled search. |
| `user` | Opt | string | The user who scheduled the search. |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

### `View_Activity`

**Object** `View_Activity` · **Parent** `BaseEvent` · **Fields** 9  
**Constraint** `index=_internal sourcetype=splunk_web_access method=GET status=200`

| Field | St | Type | Description |
|---|:--:|---|---|
| `app` | Req | string | The app name which contains the view. |
| `view` | Req | string | The name of the view. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `spent` | Opt | number | The amount of time spent loading the view (in milliseconds). |
| `uri` | Opt | string | The uniform resource identifier of the view activity. |
| `user` | Opt | string | The username of the user who accessed the view. |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

### `Web_Service_Errors`

**Object** `Web_Service_Errors` · **Parent** `BaseSearch` · **Fields** 5  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | The event timestamp expressed in Unix time. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `host` | Opt | string | The host on which the web service error occurred. |
| `source` | Opt | string | The source where the web service error occurred. |
| `sourcetype` | Opt | string | The source type associated with the web service error. |

### `Modular_Actions`

**Object** `Modular_Actions` · **Parent** `BaseEvent` · **Fields** 18 · **Tags** `modaction`  
**Constraint** `tag=modaction`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action_mode` | Opt | string | Specifies whether the action was executed as an ad hoc action or from a saved sea… |
| `action_name` | Opt | string | The name of the action. (Eval) |
| `action_status` | Opt | string | The status of the action. For example, 'success' or 'failure'. |
| `app` | Opt | string | The app ID of the app or add-on that owns the action. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `component` | Opt | string | The component of the modular action script involved in the event. Often used in c… |
| `duration` | Opt | number | How long the action took to complete, in milliseconds. |
| `orig_rid` | Opt | string | The rid value of a source action result, automatically added to an event if it is… |
| `orig_sid` | Opt | string | The original sid value of a source action, automatically added to an event if it… |
| `rid` | Opt | string | The id associated with the result of a specific sid. By default, this is the row… |
| `search_name` | Opt | string | The name of the correlation search that triggered the action. Blank for ad hoc ac… |
| `sid` | Opt | string | The search id, automatically assigned by splunkd. (Eval) |
| `signature` | Opt | string | The logging string associated with alert action introspection events. (Eval) |
| `user` | Opt | string | The user who triggered an ad hoc alert. Not relevant for actions triggered by sea… (Eval) |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `worker` | Opt | string | The worker performing the action. (Eval) |

**Prescribed values**  
`action_mode` = saved, adhoc  

---

## Splunk_CIM_Validation

> CIM validation harness model (self-tests the data models). **Not a normalization target** for vendor add-ons — listed for completeness.

### `Alerts`

**Object** `Alerts` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Application_State`

**Object** `Application_State` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Application_State.Missing_Extractions_Ports`

**Object** `Missing_Extractions_Ports` · **Parent** `Application_State` · **Fields** 3  
**Constraint** `All_Application_State.is_Ports=1 AND (dest="unknown" OR dest_port=0 OR transport="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `dest_port` | Opt | number | — |
| `transport` | Opt | string | — |

### `Application_State.Missing_Extractions_Processes`

**Object** `Missing_Extractions_Processes` · **Parent** `Application_State` · **Fields** 2  
**Constraint** `All_Application_State.is_Processes=1 AND (dest="unknown" OR process="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `process` | Opt | string | — |

### `Application_State.Missing_Extractions_Services`

**Object** `Missing_Extractions_Services` · **Parent** `Application_State` · **Fields** 3  
**Constraint** `All_Application_State.is_Services=1 AND (dest="unknown" OR service="unknown" OR start_mode="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `service` | Opt | string | — |
| `start_mode` | Opt | string | — |

### `Authentication`

**Object** `Authentication` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Authentication.Missing_Extractions_Authentication`

**Object** `Missing_Extractions_Authentication` · **Parent** `Authentication` · **Fields** 5  
**Constraint** `(action="unknown" OR app="unknown" OR src="unknown" OR dest="unknown" OR user="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `app` | Opt | string | — |
| `dest` | Opt | string | — |
| `src` | Opt | string | — |
| `user` | Opt | string | — |

### `Certificates`

**Object** `Certificates` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Certificates.Missing_Extractions_Certificates`

**Object** `Missing_Extractions_Certificates` · **Parent** `Certificates` · **Fields** 3  
**Constraint** `ssl_hash="unknown" OR ssl_issuer="unknown" OR ssl_subject="unknown"`

| Field | St | Type | Description |
|---|:--:|---|---|
| `ssl_hash` | Opt | string | — |
| `ssl_issuer` | Opt | string | — |
| `ssl_subject` | Opt | string | — |

### `Change_Analysis`

**Object** `Change_Analysis` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Change_Analysis.Missing_Extractions_Account_Management`

**Object** `Missing_Extractions_Account_Management` · **Parent** `Change_Analysis` · **Fields** 6  
**Constraint** `All_Changes.is_Account_Management=1 AND (action="unknown" OR command="unknown" OR dest="unknown" OR object_category="unknown" OR src="unknown" OR user="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `command` | Opt | string | — |
| `dest` | Opt | string | — |
| `object_category` | Opt | string | — |
| `src` | Opt | string | — |
| `user` | Opt | string | — |

### `Change_Analysis.Missing_Extractions_Endpoint_Changes`

**Object** `Missing_Extractions_Endpoint_Changes` · **Parent** `Change_Analysis` · **Fields** 7  
**Constraint** `All_Changes.is_Endpoint_Changes=1 AND (action="unknown" OR dest="unknown" OR object="unknown" OR object_category="unknown" OR object_path="unknown" OR status="unknown" OR user="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `dest` | Opt | string | — |
| `object` | Opt | string | — |
| `object_category` | Opt | string | — |
| `object_path` | Opt | string | — |
| `status` | Opt | string | — |
| `user` | Opt | string | — |

### `Change_Analysis.Missing_Extractions_Filesystem_Changes`

**Object** `Missing_Extractions_Filesystem_Changes` · **Parent** `Change_Analysis` · **Fields** 15  
**Constraint** `All_Changes.is_Endpoint_Changes=1 AND (object_category=file OR object_category=directory) AND (action="unknown" OR dest="unknown" OR object="unknown" OR object_category="unknown" OR object_path="unknown" OR status="unknown" OR user="unknown" OR file_access_time=0 OR file_create_time=0 OR file_hash="unknown" OR file_modify_time=0 OR file_name="unknown" OR file_path="unknown" OR file_acl="unknown" OR file_size="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `dest` | Opt | string | — |
| `file_access_time` | Opt | number | — |
| `file_acl` | Opt | string | — |
| `file_create_time` | Opt | number | — |
| `file_hash` | Opt | string | — |
| `file_modify_time` | Opt | number | — |
| `file_name` | Opt | string | — |
| `file_path` | Opt | string | — |
| `file_size` | Opt | number | — |
| `object` | Opt | string | — |
| `object_category` | Opt | string | — |
| `object_path` | Opt | string | — |
| `status` | Opt | string | — |
| `user` | Opt | string | — |

### `Change_Analysis.Missing_Extractions_Network_Changes`

**Object** `Missing_Extractions_Network_Changes` · **Parent** `Change_Analysis` · **Fields** 4  
**Constraint** `All_Changes.is_Network_Changes=1 AND (action="unknown" OR command="unknown" OR dvc="unknown" OR user="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `command` | Opt | string | — |
| `dvc` | Opt | string | — |
| `user` | Opt | string | — |

### `Change_Analysis.Missing_Extractions_Restarts`

**Object** `Missing_Extractions_Restarts` · **Parent** `Change_Analysis` · **Fields** 4  
**Constraint** `All_Changes.is_Network_Changes=1 AND (action="unknown" OR change_type="unknown") AND (reboot* OR restart*) sourcetype!=stash`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `command` | Opt | string | — |
| `dvc` | Opt | string | — |
| `user` | Opt | string | — |

### `Compute_Inventory`

**Object** `Compute_Inventory` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Compute_Inventory.Missing_Extractions_CPU`

**Object** `Missing_Extractions_CPU` · **Parent** `Compute_Inventory` · **Fields** 4  
**Constraint** `All_Inventory.is_CPU=1 AND (dest="unknown" OR NOT (cpu_cores=* OR cpu_count=* OR cpu_mhz=*))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `cpu_cores` | Opt | number | — |
| `cpu_count` | Opt | number | — |
| `cpu_mhz` | Opt | number | — |
| `dest` | Opt | string | — |

### `Compute_Inventory.Missing_Extractions_Memory`

**Object** `Missing_Extractions_Memory` · **Parent** `Compute_Inventory` · **Fields** 2  
**Constraint** `All_Inventory.is_Memory=1 AND (dest="unknown" OR NOT (mem=*))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `mem` | Opt | string | — |

### `Compute_Inventory.Missing_Extractions_Network`

**Object** `Missing_Extractions_Network` · **Parent** `Compute_Inventory` · **Fields** 6  
**Constraint** `All_Inventory.is_Network=1 AND (dest="unknown" OR NOT (interface=* OR ip=* OR mac=* OR name=* OR dns=*))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `dns` | Opt | string | — |
| `interface` | Opt | string | — |
| `ip` | Opt | string | — |
| `mac` | Opt | string | — |
| `name` | Opt | string | — |

### `Compute_Inventory.Missing_Extractions_Storage`

**Object** `Missing_Extractions_Storage` · **Parent** `Compute_Inventory` · **Fields** 3  
**Constraint** `All_Inventory.is_Storage=1 AND (dest="unknown" OR NOT (mount=* OR storage=*))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `mount` | Opt | string | — |
| `storage` | Opt | string | — |

### `Compute_Inventory.Missing_Extractions_OS`

**Object** `Missing_Extractions_OS` · **Parent** `Compute_Inventory` · **Fields** 3  
**Constraint** `All_Inventory.is_OS=1 AND (dest="unknown" OR NOT (os=* OR version=*))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `os` | Opt | string | — |
| `version` | Opt | string | — |

### `Databases`

**Object** `Databases` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Email`

**Object** `Email` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Email.Missing_Extractions_All_Email`

**Object** `Missing_Extractions_All_Email` · **Parent** `Email` · **Fields** 5  
**Constraint** `(action="unknown" OR dest="unknown" OR src="unknown" OR src_user="unknown" OR vendor_product="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `dest` | Opt | string | — |
| `src` | Opt | string | — |
| `src_user` | Opt | string | — |
| `vendor_product` | Opt | string | — |

### `Interprocess_Messaging`

**Object** `Interprocess_Messaging` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Intrusion_Detection`

**Object** `Intrusion_Detection` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Intrusion_Detection.Missing_Extractions_IDS`

**Object** `Missing_Extractions_IDS` · **Parent** `Intrusion_Detection` · **Fields** 9  
**Constraint** `(dvc="unknown" OR ids_type="unknown" OR category="unknown" OR signature="unknown" OR severity="unknown" OR src="unknown" OR dest="unknown" OR user="unknown" OR vendor_product="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `category` | Opt | string | — |
| `dest` | Opt | string | — |
| `dvc` | Opt | string | — |
| `ids_type` | Opt | string | — |
| `severity` | Opt | string | — |
| `signature` | Opt | string | — |
| `src` | Opt | string | — |
| `user` | Opt | string | — |
| `vendor_product` | Opt | string | — |

### `JVM`

**Object** `JVM` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Malware`

**Object** `Malware` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Malware.Missing_Extractions_Malware_Attacks`

**Object** `Missing_Extractions_Malware_Attacks` · **Parent** `Malware` · **Fields** 7  
**Constraint** `(action="unknown" OR category="unknown" OR signature="unknown" OR dest="unknown" OR dest_nt_domain="unknown" OR user="unknown" OR vendor_product="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `category` | Opt | string | — |
| `dest` | Opt | string | — |
| `dest_nt_domain` | Opt | string | — |
| `signature` | Opt | string | — |
| `user` | Opt | string | — |
| `vendor_product` | Opt | string | — |

### `Malware.Missing_Extractions_Malware_Operations`

**Object** `Missing_Extractions_Malware_Operations` · **Parent** `Malware` · **Fields** 4  
**Constraint** `dest="unknown" OR dest_nt_domain="unknown" OR product="unknown" OR (NOT (product_version=* OR signature_version=*)) OR vendor="unknown"`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `dest_nt_domain` | Opt | string | — |
| `product` | Opt | string | — |
| `vendor` | Opt | string | — |

### `Network_Resolution`

**Object** `Network_Resolution` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Network_Resolution.Missing_Extractions_DNS`

**Object** `Missing_Extractions_DNS` · **Parent** `Network_Resolution` · **Fields** 6  
**Constraint** `src="unknown" OR dest="unknown" OR answer="unknown" OR query="unknown" OR message_type="unknown" OR reply_code="unknown"`

| Field | St | Type | Description |
|---|:--:|---|---|
| `answer` | Opt | string | — |
| `dest` | Opt | string | — |
| `message_type` | Opt | string | — |
| `query` | Opt | string | — |
| `reply_code` | Opt | string | — |
| `src` | Opt | string | — |

### `Network_Sessions`

**Object** `Network_Sessions` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Network_Sessions.Missing_Extractions_Network_Sessions`

**Object** `Missing_Extractions_Network_Sessions` · **Parent** `Network_Sessions` · **Fields** 1  
**Constraint** `(dest_ip="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest_ip` | Opt | string | — |

### `Network_Traffic`

**Object** `Network_Traffic` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Network_Traffic.Missing_Extractions_Network_Traffic`

**Object** `Missing_Extractions_Network_Traffic` · **Parent** `Network_Traffic` · **Fields** 9  
**Constraint** `(action="unknown" OR dvc="unknown" OR rule="unknown" OR transport="unknown" OR src="unknown" OR src_port=0 OR dest="unknown" OR dest_port=0 OR vendor_product="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `dest` | Opt | string | — |
| `dest_port` | Opt | number | — |
| `dvc` | Opt | string | — |
| `rule` | Opt | string | — |
| `src` | Opt | string | — |
| `src_port` | Opt | number | — |
| `transport` | Opt | string | — |
| `vendor_product` | Opt | string | — |

### `Performance`

**Object** `Performance` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Performance.Missing_Extractions_Perf_CPU`

**Object** `Missing_Extractions_Perf_CPU` · **Parent** `Performance` · **Fields** 5  
**Constraint** `All_Performance.is_CPU=1 AND ((dest="unknown" OR NOT (cpu_load_mhz=* OR cpu_load_percent=* OR cpu_time=* OR cpu_user_percent=*)))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `cpu_load_mhz` | Opt | number | — |
| `cpu_load_percent` | Opt | number | — |
| `cpu_time` | Opt | number | — |
| `cpu_user_percent` | Opt | number | — |
| `dest` | Opt | string | — |

### `Performance.Missing_Extractions_Perf_Facilities`

**Object** `Missing_Extractions_Perf_Facilities` · **Parent** `Performance` · **Fields** 4  
**Constraint** `All_Performance.is_Facilities=1 AND ((dest="unknown" OR NOT (temperature=* OR power=* OR fan_speed=*)))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `fan_speed` | Opt | number | — |
| `power` | Opt | number | — |
| `temperature` | Opt | number | — |

### `Performance.Missing_Extractions_Perf_Memory`

**Object** `Missing_Extractions_Perf_Memory` · **Parent** `Performance` · **Fields** 4  
**Constraint** `All_Performance.is_Memory=1 AND ((dest="unknown" OR NOT (mem=* OR mem_committed=* OR mem_free=* OR mem_used=*)))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `mem` | Opt | number | — |
| `mem_free` | Opt | number | — |
| `mem_used` | Opt | number | — |

### `Performance.Missing_Extractions_Perf_Storage`

**Object** `Missing_Extractions_Perf_Storage` · **Parent** `Performance` · **Fields** 7  
**Constraint** `All_Performance.is_Storage=1 AND ((dest="unknown" OR NOT (mount=* OR storage=* OR storage_free=* OR storage_used=* OR storage_free_percent=* OR storage_used_percent=*)))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `mount` | Opt | string | — |
| `storage` | Opt | number | — |
| `storage_free` | Opt | number | — |
| `storage_free_percent` | Opt | number | — |
| `storage_used` | Opt | number | — |
| `storage_used_percent` | Opt | number | — |

### `Performance.Missing_Extractions_Perf_Network`

**Object** `Missing_Extractions_Perf_Network` · **Parent** `Performance` · **Fields** 3  
**Constraint** `All_Performance.is_Network=1 AND ((dest="unknown" OR NOT (thruput=* OR thruput_max=*)))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `thruput` | Opt | number | — |
| `thruput_max` | Opt | number | — |

### `Performance.Missing_Extractions_Perf_Timesync`

**Object** `Missing_Extractions_Perf_Timesync` · **Parent** `Performance` · **Fields** 2 · **Tags** `time`, `synchronize`  
**Constraint** `All_Performance.is_OS=1 AND (tag=time tag=synchronize (dest="unknown" OR action="unknown"))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `dest` | Opt | string | — |

### `Performance.Missing_Extractions_Perf_Uptime`

**Object** `Missing_Extractions_Perf_Uptime` · **Parent** `Performance` · **Fields** 2 · **Tags** `uptime`  
**Constraint** `All_Performance.is_OS=1 AND (tag=uptime (dest="unknown" OR uptime="unknown"))`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `dest` | Opt | string | — |

### `Splunk_Audit`

**Object** `Splunk_Audit` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Ticket_Management`

**Object** `Ticket_Management` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Ticket_Management.Missing_Extractions_All_Ticket_Managment`

**Object** `Missing_Extractions_All_Ticket_Managment` · **Parent** `Ticket_Management` · **Fields** 2  
**Constraint** `dest="unknown" OR ticket_id="unknown"`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `ticket_id` | Opt | string | — |

### `Ticket_Management.Missing_Extractions_Incident`

**Object** `Missing_Extractions_Incident` · **Parent** `Ticket_Management` · **Fields** 2  
**Constraint** `All_Ticket_Management.is_Incident=1 AND (dest="unknown" OR incident="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `incident` | Opt | string | — |

### `Ticket_Management.Missing_Extractions_Problem`

**Object** `Missing_Extractions_Problem` · **Parent** `Ticket_Management` · **Fields** 2  
**Constraint** `All_Ticket_Management.is_Problem=1 AND (dest="unknown" OR problem="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `problem` | Opt | string | — |

### `Ticket_Management.Missing_Extractions_Change`

**Object** `Missing_Extractions_Change` · **Parent** `Ticket_Management` · **Fields** 2  
**Constraint** `All_Ticket_Management.is_Change=1 AND (dest="unknown" OR NOT change="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `change` | Opt | string | — |
| `dest` | Opt | string | — |

### `Updates`

**Object** `Updates` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Updates.Missing_Extractions_Updates`

**Object** `Missing_Extractions_Updates` · **Parent** `Updates` · **Fields** 5  
**Constraint** `(dest="unknown" OR signature="unknown" OR signature_id="unknown" OR status="unknown" OR vendor_product="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Opt | string | — |
| `signature` | Opt | string | — |
| `signature_id` | Opt | string | — |
| `status` | Opt | string | — |
| `vendor_product` | Opt | string | — |

### `Vulnerabilities`

**Object** `Vulnerabilities` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Vulnerabilities.Missing_Extractions_Vulnerabilities`

**Object** `Missing_Extractions_Vulnerabilities` · **Parent** `Vulnerabilities` · **Fields** 6  
**Constraint** `(dvc="unknown" OR category="unknown" OR signature="unknown" OR severity="unknown" OR dest="unknown" OR vendor_product="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `category` | Opt | string | — |
| `dest` | Opt | string | — |
| `dvc` | Opt | string | — |
| `severity` | Opt | string | — |
| `signature` | Opt | string | — |
| `vendor_product` | Opt | string | — |

### `Web`

**Object** `Web` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

### `Web.Missing_Extractions_Web`

**Object** `Missing_Extractions_Web` · **Parent** `Web` · **Fields** 11  
**Constraint** `(action="unknown" OR dest="unknown" OR http_content_type="unknown" OR http_method="unknown" OR http_referrer="unknown" OR http_user_agent="unknown" OR src="unknown" OR status="unknown" OR url="unknown" OR user="unknown" OR vendor_product="unknown")`

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Opt | string | — |
| `dest` | Opt | string | — |
| `http_content_type` | Opt | string | — |
| `http_method` | Opt | string | — |
| `http_referrer` | Opt | string | — |
| `http_user_agent` | Opt | string | — |
| `src` | Opt | string | — |
| `status` | Opt | string | — |
| `url` | Opt | string | — |
| `user` | Opt | string | — |
| `vendor_product` | Opt | string | — |

### `Untagged_Events`

**Object** `Untagged_Events` · **Parent** `BaseSearch` · **Fields** 4  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | — |
| `host` | Opt | string | — |
| `source` | Opt | string | — |
| `sourcetype` | Opt | string | — |

---

## Ticket_Management

### `All_Ticket_Management`

**Object** `All_Ticket_Management` · **Parent** `BaseEvent` · **Fields** 25 · **Tags** `ticketing`  
**Constraint** ``(`cim_Ticket_Management_indexes`) tag=ticketing``

| Field | St | Type | Description |
|---|:--:|---|---|
| `affect_dest` | Opt | string | Destinations affected by the service request. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `comments` | Opt | string | Comments about the service request. |
| `description` | Opt | string | The description of the service request. |
| `dest` | Opt | string | The destination of the service request. You can alias this from more specific fie… (Eval) |
| `dest_bunit` | Opt | string | The business unit of the destination. |
| `dest_category` | Opt | string | The category of the destination. |
| `dest_priority` | Opt | string | The priority of the destination. |
| `priority` | Opt | string | The relative priority of the service request. |
| `severity` | Opt | string | The relative severity of the service request. |
| `severity_id` | Opt | string | The numeric or vendor specific severity indicator corresponding to the event seve… |
| `splunk_id` | Opt | string | The unique identifier of the service request as it pertains to Splunk. For exampl… |
| `splunk_realm` | Opt | string | The Splunk application or use case associated with the unique identifier (splunk_… |
| `src_user` | Opt | string | The user or entity that created or triggered the service request, if applicable. |
| `src_user_bunit` | Opt | string | The business unit associated with the user or entity that triggered the service r… |
| `src_user_category` | Opt | string | The category associated with the user or entity that triggered the service reques… |
| `src_user_priority` | Opt | string | The priority associated with the user or entity that triggered the service reques… |
| `status` | Opt | string | The relative status of the service request. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `ticket_id` | Opt | string | An identification name, code, or number for the service request. (Eval) |
| `time_submitted` | Opt | timestamp | The time that the src_user submitted the service request. |
| `user` | Opt | string | The name of the user or entity that is assigned to carry out the service request… |
| `user_bunit` | Opt | string | The business unit associated with the user or entity that is assigned to carry ou… |
| `user_category` | Opt | string | The category associated with the user or entity that is assigned to carry out the… |
| `user_priority` | Opt | string | The priority of the user or entity that is assigned to carry out the service requ… |

### `All_Ticket_Management.Change`

**Object** `Change` · **Parent** `All_Ticket_Management` · **Fields** 1 · **Tags** `change`  
**Constraint** `tag=change`

| Field | St | Type | Description |
|---|:--:|---|---|
| `change` | Opt | string | Designation for a request for change (RFC) that is raised to modify an IT service… (Eval) |

### `All_Ticket_Management.Incident`

**Object** `Incident` · **Parent** `All_Ticket_Management` · **Fields** 1 · **Tags** `incident`  
**Constraint** `tag=incident`

| Field | St | Type | Description |
|---|:--:|---|---|
| `incident` | Opt | string | The incident that triggered the service request. Can be a rare occurrence, or som… (Eval) |

### `All_Ticket_Management.Problem`

**Object** `Problem` · **Parent** `All_Ticket_Management` · **Fields** 1 · **Tags** `problem`  
**Constraint** `tag=problem`

| Field | St | Type | Description |
|---|:--:|---|---|
| `problem` | Opt | string | When multiple occurrences of related incidents are observed, they are collectivel… (Eval) |

---

## Updates

### `Updates`

**Object** `Updates` · **Parent** `BaseEvent` · **Fields** 16 · **Tags** `update`, `status`  
**Constraint** ``(`cim_Updates_indexes`) tag=update tag=status``

| Field | St | Type | Description |
|---|:--:|---|---|
| `dest` | Rec | string | The system that is affected by the patch change. You can alias this from more spe… (Eval) |
| `signature` | Rec | string | The name of the patch requirement detected on the client (the dest), such as MS08… (Eval) |
| `signature_id` | Rec | string | The ID of the patch requirement detected on the client (the src). Note: Use signa… (Eval) |
| `status` | Rec | string | Indicates the status of a given patch requirement. (Eval) |
| `vendor_product` | Rec | string | The vendor and product of the patch monitoring product, such as Lumension Patch M… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_should_update` | Opt | boolean | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc` | Opt | string | The device that detected the patch event, such as a patching or configuration man… |
| `file_hash` | Opt | string | The checksum of the patch package that was installed or attempted. |
| `file_name` | Opt | string | The name of the patch package that was installed or attempted. |
| `severity` | Opt | string | The severity associated with the patch event. |
| `severity_id` | Opt | string | The numeric or vendor specific severity indicator corresponding to the event seve… |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |

**Prescribed values**  
`status` = available, installed, invalid, restart required, failure  
`severity` = critical, high, medium, low, informational  

### `Update_Errors`

**Object** `Update_Errors` · **Parent** `BaseSearch` · **Fields** 5  
**Constraint** _(none — derived dataset; inherits parent)_

| Field | St | Type | Description |
|---|:--:|---|---|
| `_time` | Opt | timestamp | The event timestamp expressed in Unix time. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `host` | Opt | string | The host associated with the search. |
| `source` | Opt | string | The source associated with the search. |
| `sourcetype` | Opt | string | The source type associated with the search. |

---

## Vulnerabilities

### `Vulnerabilities`

**Object** `Vulnerabilities` · **Parent** `BaseEvent` · **Fields** 28 · **Tags** `vulnerability`, `report`  
**Constraint** ``(`cim_Vulnerabilities_indexes`) tag=vulnerability tag=report``

| Field | St | Type | Description |
|---|:--:|---|---|
| `category` | Rec | string | The category of the discovered vulnerability, such as DoS. Note: This field is a… (Eval) |
| `cve` | Rec | string | The identifier provided in the Common Vulnerabilities and Exposures index (search… (Eval) |
| `dest` | Rec | string | The host with the discovered vulnerability. You can alias this from more specific… (Eval) |
| `dvc` | Rec | string | The system that discovered the vulnerability. You can alias this from more specif… (Eval) |
| `severity` | Rec | string | The severity of the vulnerability detection event. Specific values are required… (Eval) |
| `signature` | Rec | string | The name of the vulnerability detected on the host, such as HPSBMU02785 SSRT10052… (Eval) |
| `vendor_product` | Rec | string | The vendor and product that detected the vulnerability. This field can be automat… (Eval) |
| `bugtraq` | Opt | string | The identifier in the vulnerability database provided by the Security Focus websi… (Eval) |
| `cert` | Opt | string | The identifier in the vulnerability database provided by the US Computer Emergenc… (Eval) |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `cvss` | Opt | number | Numeric indicator of the common vulnerability scoring system. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dvc_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `msft` | Opt | string | The Microsoft Security Advisory number (http://technet.microsoft.com/en-us/securi… (Eval) |
| `mskb` | Opt | string | The Microsoft Knowledge Base article number (http://support.microsoft.com/kb/). (Eval) |
| `severity_id` | Opt | string | The numeric or vendor specific severity indicator corresponding to the event seve… |
| `signature_id` | Opt | string | The unique identifier or event code of the event signature. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `url` | Opt | string | The URL involved in the discovered vulnerability. |
| `user` | Opt | string | The user involved in the discovered vulnerability. |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `xref` | Opt | string | A cross-reference identifier associated with the vulnerability. In most cases, th… (Eval) |

**Prescribed values**  
`severity` = critical, high, medium, low, informational  

---

## Web

### `Web`

**Object** `Web` · **Parent** `BaseEvent` · **Fields** 41 · **Tags** `web`  
**Constraint** ``(`cim_Web_indexes`) tag=web``

| Field | St | Type | Description |
|---|:--:|---|---|
| `action` | Rec | string | The action taken by the server or proxy. (Eval) |
| `bytes` | Rec | number | The total number of bytes transferred (bytes_in + bytes_out). (Eval) |
| `bytes_in` | Rec | number | The number of inbound bytes transferred. (Eval) |
| `bytes_out` | Rec | number | The number of outbound bytes transferred. (Eval) |
| `dest` | Rec | string | The destination of the network traffic (the remote host). You can alias this from… (Eval) |
| `http_content_type` | Rec | string | The content-type of the requested HTTP resource. (Eval) |
| `http_method` | Rec | string | The HTTP method used in the request. (Eval) |
| `http_referrer` | Rec | string | The HTTP referrer used in the request. The W3C specification and many implementat… (Eval) |
| `http_referrer_domain` | Rec | string | The domain name contained within the HTTP referrer used in the request. (Rex) |
| `http_user_agent` | Rec | string | The user agent used in the request. (Eval) |
| `src` | Rec | string | The source of the network traffic (the client requesting the connection). (Eval) |
| `status` | Rec | string | The HTTP response code indicating the status of the proxy request. (Eval) |
| `url` | Rec | string | The URL of the requested HTTP resource. (Eval) |
| `url_domain` | Rec | string | The domain name contained within the URL of the requested HTTP resource. (Rex) |
| `user` | Rec | string | The user that requested the HTTP resource. (Eval) |
| `vendor_product` | Rec | string | The vendor and product of the proxy server, such as Squid Proxy Server. This fiel… (Eval) |
| `app` | Opt | string | The application detected or hosted by the server/site such as wordpress, splunk… |
| `cached` | Opt | boolean | Indicates whether the event data is cached or not. |
| `category` | Opt | string | The category of traffic, such as may be provided by a proxy server. |
| `cim_entity_zone` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `cookie` | Opt | string | The cookie file recorded in the event. |
| `dest_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `dest_ip` | Opt | string | The IP address of the destination. |
| `dest_port` | Opt | number | The destination port of the web traffic. |
| `dest_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `duration` | Opt | number | The time taken by the proxy event, in milliseconds. |
| `http_user_agent_length` | Opt | number | The length of the user agent used in the request. (Eval) |
| `response_time` | Opt | number | The amount of time it took to receive a response, if applicable, in milliseconds. |
| `site` | Opt | string | The virtual site which services the request, if applicable. |
| `src_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `src_ip` | Opt | string | The ip address of the source. |
| `src_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `tag` | Opt | string | This automatically generated field is used to access tags from within data models… |
| `uri_path` | Opt | string | The path of the resource served by the webserver or proxy. |
| `uri_query` | Opt | string | The path of the resource requested by the client. |
| `url_length` | Opt | number | The length of the URL. (Eval) |
| `user_bunit` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_category` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |
| `user_priority` | Opt | string | Auto-set by ES asset/identity correlation — do not extract. |

**Prescribed values**  
`http_method` = GET, PUT, POST, DELETE, HEAD, OPTIONS, CONNECT, TRACE  
`status` = 100, 101, 102, 200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302, 303, 304, 305, 306, 307, 308, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 422, 423, 424, 426, 428, 429, 431, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511  
`cached` = true, false, 1, 0  

### `Web.Storage`

**Object** `Storage` · **Parent** `Web` · **Fields** 3 · **Tags** `storage`  
**Constraint** `tag=storage`

| Field | St | Type | Description |
|---|:--:|---|---|
| `error_code` | Opt | string | The error code that occurred while accessing the storage account. |
| `operation` | Opt | string | The operation performed on the storage account. |
| `storage_name` | Opt | string | The name of the bucket or storage account. |

---

<p align="center"><sub>Splunk CIM 8.5.0 reference (`splunk_data_model_objects_fields_850.csv`) · May 19, 2026 · Machine Data Insights Inc. — Data Refinery</sub></p>
