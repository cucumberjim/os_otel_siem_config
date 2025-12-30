# OpenTelemetry Collector Configurations for Windows and Linux Event Logs

This repository contains comprehensive OpenTelemetry Collector configurations for ingesting and transforming Windows Event Logs and Linux system logs (auditd and journald) from XML/raw format to human-readable structured data with **Splunk CIM** and **Google SecOps UDM** compliant field mappings.

## Overview

These configurations use the OpenTelemetry Collector to ingest event logs and transform processors to:
1. Convert Event IDs and log types to human-readable descriptions
2. Extract EventData/structured fields into attributes
3. Map to **Splunk Common Information Model (CIM)** fields for SIEM compatibility
4. Map to **Google SecOps Unified Data Model (UDM)** fields for Chronicle SIEM
5. Use field aliases where possible to avoid data duplication

## Configuration Files

### Windows Event Logs

| Configuration File | Event Log Channel | Description |
|-------------------|-------------------|-------------|
| `system-eventlog-config.yaml` | System | Service Control Manager, Kernel events, Disk events, DCOM, Network |
| `application-eventlog-config.yaml` | Application | Application errors, MSI installer, .NET Runtime, ESENT, SideBySide, VSS |
| `security-eventlog-config.yaml` | Security | Authentication, Authorization, Account Management, Process Tracking, Audit |
| `taskscheduler-eventlog-config.yaml` | Microsoft-Windows-TaskScheduler/Operational | Task registration, execution, triggers, and completion |
| `openssh-eventlog-config.yaml` | OpenSSH/Operational | SSH connections, authentication, sessions, port forwarding |
| `winrm-eventlog-config.yaml` | Microsoft-Windows-WinRM/Operational | WinRM connections, commands, authentication, errors |
| `powershell-eventlog-config.yaml` | Microsoft-Windows-PowerShell/Operational | PowerShell commands, script blocks, remoting, security |
| `powershellcore-eventlog-config.yaml` | PowerShellCore/Operational | PowerShell Core 7+ commands, script blocks, remoting |
| `capi2-eventlog-config.yaml` | Microsoft-Windows-CAPI2/Operational | Certificate validation, chain building, CRL/OCSP |

### Linux System Logs

| Configuration File | Log Source | Description |
|-------------------|------------|-------------|
| `linux-auditd-config.yaml` | /var/log/audit/audit.log | Linux auditd events with SYSCALL, authentication, process execution |
| `linux-journald-config.yaml` | systemd journal | Core OS services (sshd, sudo, systemd, firewall, network) |

## Features

### Event Processing
- **Event ID Translation**: Maps numeric Event IDs to human-readable descriptions
- **EventData Parsing**: Extracts XML EventData fields into structured attributes
- **Categorization**: Assigns logical categories (e.g., "Authentication", "Service Control Manager")
- **Severity Mapping**: Sets appropriate severity levels (info, warning, error, critical)
- **Action Tagging**: Adds action tags for operations (e.g., "logon_success", "service_started")

### Splunk CIM Compliance

All configurations include mappings to [Splunk Common Information Model](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) fields:

#### Universal CIM Fields
- `vendor` - Log source vendor (e.g., "Microsoft", "Linux")
- `vendor_product` - Vendor and product (e.g., "Microsoft Windows", "Linux Auditd")
- `product` - Product name
- `signature` - Event description/name
- `signature_id` - Event ID
- `action` - Action performed (success, failure, allowed, blocked, etc.)
- `result` - Operation result (success, failure)
- `tag` - Event classification tag(s)
- `app` - Application/provider name

#### Authentication Data Model Fields
- `user` - Username
- `src` / `src_ip` / `src_port` - Source IP address and port
- `dest` / `dest_host` - Destination hostname
- `src_user` - Source user (who initiated action)

#### Endpoint Data Model Fields
- `process` / `process_name` - Process name
- `process_path` - Process executable path
- `process_id` - Process ID (PID)
- `parent_process_id` - Parent process ID
- `process_exec` - Process command line

#### Change Data Model Fields
- `object` - Object being modified
- `object_category` - Type of object (file, service, user, etc.)
- `object_path` - Path to object

### Google SecOps UDM Compliance

All configurations include mappings to [Google SecOps Unified Data Model](https://cloud.google.com/chronicle/docs/reference/udm-field-list) fields:

#### Metadata Fields
- `metadata.vendor_name` - Vendor name
- `metadata.product_name` - Product name
- `metadata.log_type` - Log type (WINEVTLOG, AUDITD, SYSLOG)
- `metadata.event_type` - UDM event type (USER_LOGIN, PROCESS_LAUNCH, etc.)

#### Principal Fields (Who performed the action)
- `principal.hostname` - Source hostname
- `principal.user.userid` - User ID/SID
- `principal.user.user_display_name` - Username
- `principal.ip` / `principal.port` - Network information
- `principal.process.pid` - Process ID
- `principal.process.command_line` - Command line
- `principal.process.file.full_path` - Process path

#### Target Fields (Object of the action)
- `target.hostname` - Target hostname
- `target.user.userid` - Target user ID
- `target.user.user_display_name` - Target username
- `target.file.full_path` - File path
- `target.resource.name` - Resource name (service, etc.)

#### Security Result Fields
- `security_result.action` - ALLOW, BLOCK, etc.
- `security_result.severity` - LOW, MEDIUM, HIGH, CRITICAL
- `security_result.summary` - Event summary

#### Network Fields
- `network.ip_protocol` - IP protocol (TCP, UDP)
- `network.application_protocol` - Application protocol (SSH, HTTP, etc.)

## Linux-Specific Features

### Auditd Configuration
- Parses auditd key-value format
- Handles core audit record types (USER_AUTH, EXECVE, SYSCALL, SERVICE_START, etc.)
- Marks unhandled (non-core OS) events with `event.handled = false`
- Maps audit types to CIM/UDM event types

### Journald Configuration
- Filters core OS services (sshd, sudo, systemd, firewalld, NetworkManager, kernel)
- Marks application logs as `event.handled = false` with minimal parsing
- Parses SSH, sudo/su, and systemd service messages
- Maps journal priority to severity levels

## Extracted Attributes

### Common Attributes (All Logs)
- `event.record_id` - Unique event record identifier
- `event.provider` - Event provider name
- `event.id` - Numeric event ID
- `event.description` - Human-readable event description
- `event.category` - Event category
- `event.severity` - Event severity level
- `event.level` - Original event level
- `event.created` - Event timestamp
- `host.name` - Computer name
- `user.sid` - User Security Identifier (Windows)
- `process.pid` - Process ID
- `process.thread_id` - Thread ID

### Log-Specific Attributes

**Security Events:**
- `subject.user_name`, `target.user_name` - Source and target users
- `source.ip`, `source.port` - Network source
- `logon.type` - Logon type (2=Interactive, 3=Network, etc.)
- `authentication.package` - Auth package (Kerberos, NTLM, etc.)

**PowerShell Events:**
- `powershell.command`, `powershell.script_block` - Command and script content
- `powershell.script_block_id` - Script block identifier
- `powershell.host_name`, `powershell.engine_version` - PowerShell environment

**SSH Events (Windows & Linux):**
- `ssh.user`, `ssh.auth_method` - User and authentication method
- `ssh.command`, `ssh.key_type` - Command and key information

**Auditd Events:**
- `audit.uid`, `audit.auid` - User and audit user IDs
- `audit.exe`, `audit.comm` - Executable and command
- `audit.result` - Operation result

**Journald Events:**
- `journal.unit`, `journal.syslog_identifier` - Systemd unit and identifier
- `journal.priority` - Syslog priority
- `severity` - Mapped severity (emergency, alert, critical, error, warning, notice, info, debug)

## Usage

### Prerequisites

**Windows:**
- OpenTelemetry Collector Contrib installed
- Administrator permissions to read Event Logs
- Target export destination configured

**Linux (Rocky 9):**
- OpenTelemetry Collector Contrib installed
- Read access to /var/log/audit/audit.log (auditd)
- Read access to /var/log/journal (journald)
- Target export destination configured

### Running a Configuration

**Windows:**
```powershell
otelcol-contrib.exe --config=security-eventlog-config.yaml
```

**Linux:**
```bash
sudo ./otelcol-contrib --config=linux-auditd-config.yaml
```

### Exporter Configuration

Each configuration includes examples for common exporters. Uncomment and configure as needed:

**Splunk HEC:**
```yaml
exporters:
  splunk_hec:
    token: "your-hec-token"
    endpoint: "https://splunk:8088/services/collector"
    source: "otel"
    sourcetype: "otel:windows:security"  # or appropriate sourcetype
    index: "windows"
```

**Google SecOps (Chronicle):**
```yaml
exporters:
  googlecloud:
    project: "your-project-id"
    log_name: "windows_security"
```

**OTLP:**
```yaml
exporters:
  otlp:
    endpoint: "your-otlp-endpoint:4317"
    tls:
      insecure: false
```

### Running Multiple Logs

**Option 1: Merge configurations into a single file**

```yaml
receivers:
  windowseventlog/system:
    channel: System
    # ... system config

  windowseventlog/security:
    channel: Security
    # ... security config

service:
  pipelines:
    logs/system:
      receivers: [windowseventlog/system]
      processors: [transform/system_eventdata, transform/system_event_descriptions, transform/system_eventdata_fields, transform/system_cim, transform/system_udm]
      exporters: [splunk_hec]

    logs/security:
      receivers: [windowseventlog/security]
      processors: [transform/security_eventdata, transform/security_event_descriptions, transform/security_eventdata_fields, transform/security_cim, transform/security_udm]
      exporters: [splunk_hec]
```

**Option 2: Run multiple collector instances**
- Use different configurations for each log source
- Configure different endpoints or tags to distinguish sources

## CIM/UDM Field Mapping Examples

### Authentication Event Mapping

**Windows Security Event 4624 (Successful Logon):**

Original Fields → CIM Fields:
- `event.id: 4624` → `signature_id: 4624`
- `event.description: "Successful account logon"` → `signature: "Successful account logon"`
- `target.user_name: "jdoe"` → `user: "jdoe"`
- `source.ip: "192.168.1.100"` → `src_ip: "192.168.1.100"`
- `event.action: "logon_success"` → `action: "logon_success"`, `result: "success"`

Original Fields → UDM Fields:
- → `metadata.event_type: "USER_LOGIN"`
- `subject.user_name: "admin"` → `principal.user.user_display_name: "admin"`
- `target.user_name: "jdoe"` → `target.user.user_display_name: "jdoe"`
- `source.ip: "192.168.1.100"` → `principal.ip: "192.168.1.100"`
- → `security_result.action: "ALLOW"`, `security_result.severity: "LOW"`

### Process Execution Mapping

**Linux Auditd EXECVE Event:**

Original Fields → CIM Fields:
- `audit_type: "EXECVE"` → `signature: "Process Execution"`, `tag: "process"`
- `comm: "bash"` → `process: "bash"`, `process_name: "bash"`
- `exe: "/bin/bash"` → `process_path: "/bin/bash"`
- `pid: "1234"` → `process_id: "1234"`
- `res: "success"` → `action: "allowed"`, `result: "success"`

Original Fields → UDM Fields:
- → `metadata.event_type: "PROCESS_LAUNCH"`
- `exe: "/bin/bash"` → `principal.process.file.full_path: "/bin/bash"`
- `pid: "1234"` → `principal.process.pid: "1234"`
- `cmd: "bash script.sh"` → `principal.process.command_line: "bash script.sh"`
- → `security_result.action: "ALLOW"`, `security_result.severity: "LOW"`

## Customization

### Adding Event IDs

To add support for additional Event IDs, edit the `transform/*_event_descriptions` processor:

```yaml
- set(attributes["event.description"], "Your event description") where attributes["event.id"] == "YOUR_EVENT_ID"
- set(attributes["event.category"], "Your Category") where attributes["event.id"] == "YOUR_EVENT_ID"
- set(attributes["event.severity"], "info") where attributes["event.id"] == "YOUR_EVENT_ID"
```

### Adding CIM/UDM Mappings

CIM and UDM processors use attribute aliases to avoid data duplication. To add custom mappings:

```yaml
# In transform/*_cim processor
- set(attributes["cim_field"], attributes["original_field"]) where attributes["original_field"] != nil

# In transform/*_udm processor
- set(attributes["metadata.event_type"], "UDM_EVENT_TYPE") where attributes["condition"] == "value"
```

### Handling Application Logs (Linux)

Application logs (non-core OS services) in journald are marked with `event.handled = "false"` and minimal processing. To add custom application parsing:

```yaml
# In transform/journald_categorize
- set(attributes["event.handled"], "true") where attributes["_SYSTEMD_UNIT"] == "your-app.service"

# Add custom parser
transform/journald_your_app:
  log_statements:
    - context: log
      statements:
        - set(attributes["custom.field"], ...) where attributes["SYSLOG_IDENTIFIER"] == "your-app"
```

## Performance Considerations

1. **Polling Interval**: Default is 1 second. Increase for lower load: `poll_interval: 5s`
2. **Max Reads**: Default is 100 events per poll. Adjust based on event volume
3. **Start Position**: Configs use `start_at: end` for new events. Use `start_at: beginning` for historical data
4. **Processor Order**: Processors run in order - keep expensive operations last
5. **Field Aliasing**: CIM/UDM fields reference existing attributes (aliases) rather than copying data

## Troubleshooting

### Events Not Appearing

1. **Windows**: Check Event Log service is running, collector has admin rights
2. **Linux**: Check file permissions on /var/log/audit/audit.log and /var/log/journal
3. Verify channel/file names are correct
4. Review collector logs for errors

### High Memory Usage

1. Reduce `max_reads` value
2. Increase `poll_interval`
3. Filter events using conditions in transform processors
4. Use specific units in journald receiver instead of all units

### CIM/UDM Fields Not Appearing

1. Verify processors are in correct order in service pipeline
2. Check source attribute exists before aliasing
3. Review condition logic in transform statements
4. Test with verbose logging exporter first

## Event Coverage Reference

### Windows Security Events (Comprehensive)

**Authentication (4624-4625, 4634, 4647-4648, 4672)**
- 4624: Successful logon → CIM: Authentication, UDM: USER_LOGIN
- 4625: Failed logon → CIM: Authentication (failure), UDM: USER_LOGIN (blocked)
- 4634, 4647: Logoff → CIM: Authentication, UDM: USER_LOGOUT
- 4648: Explicit credentials logon → CIM: Authentication, UDM: USER_LOGIN
- 4672: Special privileges assigned → CIM: Privilege Use, UDM: USER_LOGIN

**Account Management (4720-4767)**
- 4720: User created → CIM: Change, UDM: USER_CREATION
- 4722-4725: User enabled/password changed/disabled → CIM: Change, UDM: USER_CHANGE_PERMISSIONS
- 4726: User deleted → CIM: Change, UDM: USER_DELETION
- 4738-4767: Account modifications → CIM: Change, UDM: USER_CHANGE_PERMISSIONS

**Process Tracking (4688-4689)**
- 4688: Process created → CIM: Endpoint (Process), UDM: PROCESS_LAUNCH
- 4689: Process exited → CIM: Endpoint (Process), UDM: PROCESS_TERMINATION

**Service Events (4697, 7000-7045)**
- 4697: Service installed → CIM: Endpoint (Services), UDM: SERVICE_INSTALLATION
- 7000-7045: Service lifecycle → CIM: Change, UDM: SERVICE_MODIFICATION

### Linux Auditd Events (Core OS)

**Authentication**
- USER_AUTH, USER_LOGIN → CIM: Authentication, UDM: USER_LOGIN
- USER_LOGOUT → CIM: Authentication, UDM: USER_LOGOUT
- CRED_ACQ, CRED_DISP → CIM: Authentication

**Process Execution**
- EXECVE → CIM: Endpoint (Process), UDM: PROCESS_LAUNCH
- SYSCALL → CIM: Endpoint, UDM: SYSTEM_AUDIT_LOG_UNCATEGORIZED

**Account Management**
- ADD_USER, DEL_USER → CIM: Change, UDM: USER_CREATION/USER_DELETION
- USER_CHAUTHTOK → CIM: Change, UDM: USER_CHANGE_PERMISSIONS
- ADD_GROUP, DEL_GROUP → CIM: Change, UDM: GROUP_CREATION/GROUP_DELETION

**Service Events**
- SERVICE_START, SERVICE_STOP → CIM: Change, UDM: SERVICE_MODIFICATION

## Additional Resources

- [OpenTelemetry Collector Documentation](https://opentelemetry.io/docs/collector/)
- [Windows Event Log Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/windowseventlogreceiver)
- [Journald Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/journaldreceiver)
- [Filelog Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver)
- [Transform Processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/transformprocessor)
- [Splunk CIM Documentation](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
- [Google SecOps UDM Documentation](https://cloud.google.com/chronicle/docs/reference/udm-field-list)
- [Microsoft Security Event Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Linux Audit Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)

## License

These configurations are provided as-is for use with OpenTelemetry Collector.
