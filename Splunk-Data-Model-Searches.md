# Splunk CIM Data Model Field Summary Searches

```spl
| from datamodel Authentication.Authentication
| search sourcetype IN ()
| table sourcetype tag action app authentication_method authentication_service cim_entity_zone dest dest_bunit dest_category dest_nt_domain dest_priority duration process reason reason_id response_time result session_id signature signature_id src src_bunit src_category src_nt_domain src_priority src_user src_user_bunit src_user_category src_user_id src_user_priority src_user_role src_user_type tag user user_agent user_bunit user_category user_id user_priority user_role user_type vendor_account
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Alerts.Alerts
| search sourcetype IN ()
| table sourcetype tag app body cim_entity_zone description dest dest_bunit dest_category dest_priority dest_type id mitre_technique_id severity severity_id signature signature_id src src_bunit src_category src_priority src_type subject tag type user user_bunit user_category user_name user_priority user_role user_type vendor_account vendor_region
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Application_State.All_Application_State
| search sourcetype IN ()
| table sourcetype tag dest dest_bunit dest_category dest_priority dest_requires_av dest_should_timesync dest_should_update process process_name tag user user_bunit user_category user_priority
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Application_State.All_Application_State.Ports
| search sourcetype IN ()
| table sourcetype tag dest_port transport transport_dest_port
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Application_State.All_Application_State.Processes
| search sourcetype IN ()
| table sourcetype tag cpu_load_mhz cpu_load_percent cpu_time mem_used
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Application_State.All_Application_State.Services
| search sourcetype IN ()
| table sourcetype tag service service_id start_mode status
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Certificates.All_Certificates
| search sourcetype IN ()
| table sourcetype tag cim_entity_zone dest dest_bunit dest_category dest_port dest_priority duration response_time src src_bunit src_category src_port src_priority tag transport
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Certificates.All_Certificates.SSL
| search sourcetype IN ()
| table sourcetype tag ssl_end_time ssl_engine ssl_hash ssl_issuer ssl_issuer_common_name ssl_issuer_email ssl_issuer_email_domain ssl_issuer_locality ssl_issuer_organization ssl_issuer_state ssl_issuer_street ssl_issuer_unit ssl_is_valid ssl_name ssl_policies ssl_publickey ssl_publickey_algorithm ssl_serial ssl_session_id ssl_signature_algorithm ssl_start_time ssl_subject ssl_subject_common_name ssl_subject_email ssl_subject_email_domain ssl_subject_locality ssl_subject_organization ssl_subject_state ssl_subject_street ssl_subject_unit ssl_validity_window ssl_version
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Change.All_Changes
| search sourcetype IN ()
| table sourcetype tag action change_type cim_entity_zone command dest dest_bunit dest_category dest_priority dvc object object_attrs object_category object_id object_path result result_id src src_bunit src_category src_priority status tag user user_agent user_bunit user_category user_name user_priority user_type vendor_account vendor_product vendor_region
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Change.All_Changes.Network_Changes
| search sourcetype IN ()
| table sourcetype tag dest_ip_range dest_port_range direction protocol rule_action src_ip_range src_port_range
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Change.All_Changes.Account_Management
| search sourcetype IN ()
| table sourcetype tag dest_nt_domain src_nt_domain src_user src_user_bunit src_user_category src_user_priority src_user_type src_user_name
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Change.All_Changes.Instance_Changes
| search sourcetype IN ()
| table sourcetype tag image_id instance_type
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Compute_Inventory.All_Inventory
| search sourcetype IN ()
| table sourcetype tag cim_entity_zone description dest dest_bunit dest_category dest_priority enabled family hypervisor_id serial status tag vendor_product version
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Compute_Inventory.All_Inventory.CPU
| search sourcetype IN ()
| table sourcetype tag cpu_cores cpu_count cpu_mhz
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Compute_Inventory.All_Inventory.Memory
| search sourcetype IN ()
| table sourcetype tag mem
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Compute_Inventory.All_Inventory.Network
| search sourcetype IN ()
| table sourcetype tag dest_ip dns inline_nat interface ip lb_method mac name node node_port src_ip vip_port
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Compute_Inventory.All_Inventory.Storage
| search sourcetype IN ()
| table sourcetype tag array blocksize cluster fd_max latency mount parent read_blocks read_latency read_ops storage write_blocks write_latency write_ops
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Compute_Inventory.All_Inventory.OS
| search sourcetype IN ()
| table sourcetype tag os
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Compute_Inventory.All_Inventory.User
| search sourcetype IN ()
| table sourcetype tag interactive password shell user user_bunit user_category user_id user_priority
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Compute_Inventory.All_Inventory.Virtual_OS
| search sourcetype IN ()
| table sourcetype tag hypervisor
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Compute_Inventory.Virtual_OS.Snapshot
| search sourcetype IN ()
| table sourcetype tag size snapshot time
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel DLP.DLP_Incidents
| search sourcetype IN ()
| table sourcetype tag action app category cim_entity_zone dest dest_bunit dest_category dest_priority dest_zone dlp_type dvc dvc_bunit dvc_category dvc_priority dvc_zone object object_attrs object_category object_path severity severity_id signature signature_id src src_bunit src_category src_priority src_user src_user_bunit src_user_category src_user_priority src_zone tag user user_bunit user_category user_priority vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Data_Access.Data_Access
| search sourcetype IN ()
| table sourcetype tag action app application_id cim_entity_zone dest dest_bunit dest_name dest_type dest_url dvc dvc_bunit email object object_attrs object_category object_id object_path object_size owner owner_email owner_id parent_object parent_object_category parent_object_id signature signature_id src src_bunit tag user user_agent user_bunit user_email user_group user_id user_role user_type user_name vendor_account vendor_product vendor_product_id vendor_region
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Databases.All_Databases
| search sourcetype IN ()
| table sourcetype tag cim_entity_zone dest dest_bunit dest_category dest_priority duration object response_time src src_bunit src_category src_priority tag user user_bunit user_category user_priority vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Databases.All_Databases.Database_Instance
| search sourcetype IN ()
| table sourcetype tag instance_name instance_version process_limit session_limit
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Databases.Database_Instance.Instance_Stats
| search sourcetype IN ()
| table sourcetype tag availability avg_executions dump_area_used instance_reads instance_writes number_of_users processes sga_buffer_cache_size sga_buffer_hit_limit sga_data_dict_hit_ratio sga_fixed_area_size sga_free_memory sga_library_cache_size sga_redo_log_buffer_size sga_shared_pool_size sga_sql_area_size sessions start_time tablespace_used
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Databases.Database_Instance.Session_Info
| search sourcetype IN ()
| table sourcetype tag buffer_cache_hit_ratio commits cpu_used elapsed_time logical_reads machine memory_sorts physical_reads seconds_in_wait session_id session_status table_scans wait_state wait_time
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Databases.Database_Instance.Lock_Info
| search sourcetype IN ()
| table sourcetype tag last_call_minute lock_mode lock_session_id logon_time obj_name os_pid serial_num
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Databases.All_Databases.Database_Query
| search sourcetype IN ()
| table sourcetype tag query query_id query_time records_affected
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Databases.Database_Query.Tablespace
| search sourcetype IN ()
| table sourcetype tag free_bytes tablespace_name tablespace_reads tablespace_status tablespace_writes
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Databases.Database_Query.Query_Stats
| search sourcetype IN ()
| table sourcetype tag indexes_hit query_plan_hit stored_procedures_called tables_hit
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Email.All_Email
| search sourcetype IN ()
| table sourcetype tag action cim_entity_zone delay dest dest_bunit dest_category dest_priority file_hash file_name file_size internal_message_id message_id message_info orig_dest orig_recipient orig_src protocol process process_id recipient recipient_count recipient_domain recipient_status response_time retries return_addr size src src_bunit src_category src_priority src_user src_user_bunit src_user_category src_user_domain src_user_priority status_code subject tag url user user_bunit user_category user_priority vendor_product xdelay xref
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Email.All_Email.Filtering
| search sourcetype IN ()
| table sourcetype tag filter_action filter_score signature signature_extra signature_id
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Endpoint.Ports
| search sourcetype IN ()
| table sourcetype tag cim_entity_zone creation_time dest dest_bunit dest_category dest_port dest_priority dest_requires_av dest_should_timesync dest_should_update process_guid process_id src src_bunit src_category src_port src_priority src_requires_av src_should_timesync src_should_update state tag transport transport_dest_port user_bunit user_category user_priority vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Endpoint.Processes
| search sourcetype IN ()
| table sourcetype tag action cim_entity_zone cpu_load_percent dest dest_bunit dest_category dest_is_expected dest_priority dest_requires_av dest_should_timesync dest_should_update loaded_file mem_used os original_file_name parent_process parent_process_exec parent_process_guid parent_process_hash parent_process_id parent_process_name parent_process_path parent_user process process_current_directory process_exec process_guid process_hash process_id process_integrity_level process_name process_path tag user user_bunit user_category user_id user_priority vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Endpoint.Services
| search sourcetype IN ()
| table sourcetype tag cim_entity_zone description dest dest_bunit dest_category dest_is_expected dest_priority dest_requires_av dest_should_timesync dest_should_update process_guid process_id service service_dll service_dll_hash service_dll_path service_dll_signature_exists service_dll_signature_verified service_exec service_hash service_id service_path service_signature_exists service_signature_verified service_name start_mode status tag user user_bunit user_category user_priority vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Endpoint.Filesystem
| search sourcetype IN ()
| table sourcetype tag action cim_entity_zone dest dest_bunit dest_category dest_priority dest_requires_av dest_should_timesync dest_should_update file_access_time file_acl file_create_time file_hash file_modify_time file_name file_path file_size image parent_process parent_process_exec parent_process_guid parent_process_hash parent_process_id parent_process_name parent_process_path process process_exec process_guid process_hash process_id process_path tag user user_bunit user_category user_priority vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Endpoint.Registry
| search sourcetype IN ()
| table sourcetype tag action cim_entity_zone dest dest_bunit dest_category dest_priority dest_requires_av dest_should_timesync dest_should_update image parent_process parent_process_exec parent_process_guid parent_process_hash parent_process_id parent_process_name parent_process_path process process_exec process_guid process_hash process_id process_path registry_hive registry_key_name registry_path registry_value_data registry_value_name registry_value_text registry_value_type status tag user user_bunit user_category user_priority vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Event_Signatures.Signatures
| search sourcetype IN ()
| table sourcetype tag cim_entity_zone dest dest_bunit dest_category dest_priority signature signature_id tag vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Interprocess_Messaging.All_Messaging
| search sourcetype IN ()
| table sourcetype tag cim_entity_zone dest dest_bunit dest_category dest_priority duration endpoint endpoint_version message message_consumed_time message_correlation_id message_delivered_time message_delivery_mode message_expiration_time message_id message_priority message_properties message_received_time message_redelivered message_reply_dest message_type parameters payload payload_type request_payload request_payload_type request_sent_time response_code response_payload_type response_received_time response_time return_message rpc_protocol status tag
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Intrusion_Detection.IDS_Attacks
| search sourcetype IN ()
| table sourcetype tag action category cim_entity_zone dest dest_bunit dest_category dest_ip dest_port dest_priority dest_type dvc dvc_bunit dvc_category dvc_priority file_hash file_name file_path ids_type severity severity_id signature signature_id src src_bunit src_category src_ip src_port src_priority tag transport user user_bunit user_category user_priority vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel JVM.JVM
| search sourcetype IN ()
| table sourcetype tag cim_entity_zone jvm_description tag
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel JVM.JVM.Threading
| search sourcetype IN ()
| table sourcetype tag cm_enabled cm_supported cpu_time_enabled cpu_time_supported current_cpu_time current_user_time daemon_thread_count omu_supported peak_thread_count synch_supported thread_count threads_started
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel JVM.JVM.Runtime
| search sourcetype IN ()
| table sourcetype tag process_name start_time uptime vendor_product version
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel JVM.JVM.OS
| search sourcetype IN ()
| table sourcetype tag committed_memory cpu_time free_physical_memory free_swap max_file_descriptors open_file_descriptors os os_architecture os_version physical_memory swap_space system_load total_processors
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel JVM.JVM.Compilation
| search sourcetype IN ()
| table sourcetype tag compilation_time
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel JVM.JVM.Classloading
| search sourcetype IN ()
| table sourcetype tag current_loaded total_loaded total_unloaded
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel JVM.JVM.Memory
| search sourcetype IN ()
| table sourcetype tag heap_committed heap_initial heap_max heap_used non_heap_committed non_heap_initial non_heap_max non_heap_used objects_pending
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Malware.Malware_Attacks
| search sourcetype IN ()
| table sourcetype tag action category cim_entity_zone date dest dest_bunit dest_category dest_ip dest_nt_domain dest_priority dest_requires_av file_hash file_name file_path severity severity_id signature signature_id src src_bunit src_category src_ip src_priority src_user tag url user user_bunit user_category user_priority vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Malware.Malware_Operations
| search sourcetype IN ()
| table sourcetype tag _time cim_entity_zone dest dest_bunit dest_category dest_ip dest_nt_domain dest_priority dest_requires_av product_version signature_version vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Network_Resolution.DNS
| search sourcetype IN ()
| table sourcetype tag additional_answer_count answer answer_count authority_answer_count cim_entity_zone dest dest_bunit dest_category dest_ip dest_port dest_priority duration message_type name query query_count query_type record_type reply_code reply_code_id response_time src src_bunit src_category src_ip src_port src_priority tag transaction_id transport ttl
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Network_Sessions.All_Sessions
| search sourcetype IN ()
| table sourcetype tag action cim_entity_zone dest_bunit dest_category dest_dns dest_ip dest_mac dest_nt_host dest_priority dvc duration response_time signature signature_id src_bunit src_category src_dns src_ip src_mac src_nt_host src_priority tag user user_bunit user_category user_priority vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Network_Sessions.All_Sessions.DHCP
| search sourcetype IN ()
| table sourcetype tag lease_duration lease_scope
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Network_Traffic.All_Traffic
| search sourcetype IN ()
| table sourcetype tag action app bytes bytes_in bytes_out channel cim_entity_zone dest dest_bunit dest_category dest_interface dest_ip dest_mac dest_priority dest_translated_ip dest_translated_port dest_zone direction dvc dvc_bunit dvc_category dvc_ip dvc_mac dvc_priority dvc_zone flow_id icmp_code icmp_type packets packets_in packets_out process_guid process_id protocol protocol_version response_time rule rule_id session_id src src_bunit src_category src_interface src_ip src_mac src_priority src_translated_ip src_translated_port src_zone ssid tag tcp_flag tos ttl user_bunit user_category user_priority vendor_account vendor_product vlan wifi
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Performance.All_Performance
| search sourcetype IN ()
| table sourcetype tag cim_entity_zone dest dest_bunit dest_category dest_priority dest_should_timesync dest_should_update hypervisor_id resource_type tag
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Performance.All_Performance.CPU
| search sourcetype IN ()
| table sourcetype tag cpu_load_mhz cpu_load_percent cpu_time cpu_user_percent
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Performance.All_Performance.Facilities
| search sourcetype IN ()
| table sourcetype tag fan_speed power temperature
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Performance.All_Performance.Memory
| search sourcetype IN ()
| table sourcetype tag mem mem_committed mem_free mem_used swap swap_free swap_used
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Performance.All_Performance.Storage
| search sourcetype IN ()
| table sourcetype tag array blocksize cluster fd_max fd_used latency mount parent read_blocks read_latency read_ops storage storage_free storage_free_percent storage_used storage_used_percent write_blocks write_latency write_ops
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Performance.All_Performance.Network
| search sourcetype IN ()
| table sourcetype tag thruput thruput_max
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Performance.OS.Timesync
| search sourcetype IN ()
| table sourcetype tag action dest
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Performance.OS.Uptime
| search sourcetype IN ()
| table sourcetype tag dest uptime
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Ticket_Management.All_Ticket_Management
| search sourcetype IN ()
| table sourcetype tag affect_dest cim_entity_zone comments description dest dest_bunit dest_category dest_priority priority severity severity_id splunk_id splunk_realm src_user src_user_bunit src_user_category src_user_priority status tag ticket_id time_submitted user user_bunit user_category user_priority
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Ticket_Management.All_Ticket_Management.Change
| search sourcetype IN ()
| table sourcetype tag change
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Ticket_Management.All_Ticket_Management.Incident
| search sourcetype IN ()
| table sourcetype tag incident
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Ticket_Management.All_Ticket_Management.Problem
| search sourcetype IN ()
| table sourcetype tag problem
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Updates.Updates
| search sourcetype IN ()
| table sourcetype tag action cim_entity_zone dest dest_bunit dest_category dest_priority dest_should_update dvc file_hash file_name severity severity_id signature signature_id status tag vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Updates.Update_Errors
| search sourcetype IN ()
| table sourcetype tag cim_entity_zone host source sourcetype
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Vulnerabilities.Vulnerabilities
| search sourcetype IN ()
| table sourcetype tag bugtraq category cert cim_entity_zone cve cvss dest dest_bunit dest_category dest_priority dvc dvc_bunit dvc_category dvc_priority mskb msft severity severity_id signature signature_id tag url user user_bunit user_category user_priority vendor_product xref
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Web.Web
| search sourcetype IN ()
| table sourcetype tag action app bytes bytes_in bytes_out cached category cim_entity_zone cookie dest dest_bunit dest_category dest_ip dest_port dest_priority duration http_content_type http_method http_referrer http_referrer_domain http_user_agent http_user_agent_length response_time site src src_bunit src_category src_ip src_priority status tag uri_path uri_query url url_domain url_length user user_bunit user_category user_priority vendor_product
| fieldsummary maxvals=10
| table field count distinct_count values
```

```spl
| from datamodel Web.Web.Storage
| search sourcetype IN ()
| table sourcetype tag error_code operation storage_name
| fieldsummary maxvals=10
| table field count distinct_count values
```
