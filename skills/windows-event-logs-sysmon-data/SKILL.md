# Skill: Windows Event Logs & Sysmon Telemetry Specification

## 1. Purpose
Define field mappings and parsing rules for Sysmon and Windows Security log events.

## 2. When to Use
When implementing event normalizers and creating test fixtures.

## 3. Prerequisites
Understanding of Windows Event Log schemas (Sysmon Event 1, 3, 5; Security 4624, 4688).

## 4. Implementation Steps
1. Map Sysmon Event ID 1 (Process Create): UtcTime, ProcessId, Image, CommandLine, ParentProcessId, ParentImage, User.
2. Map Sysmon Event ID 3 (Network Connect): UtcTime, ProcessId, Image, DestinationIp, DestinationPort.
3. Map Sysmon Event ID 5 (Process Terminate): UtcTime, ProcessId, Image.
4. Map Security Event ID 4624 (Logon): TimeCreated, TargetUserName, TargetDomainName, LogonType, IpAddress.
5. Map Security Event ID 4688 (Process Creation): TimeCreated, NewProcessId, NewProcessName, CommandLine, CreatorProcessId.
6. Maintain canonical null representation for fields missing in specific event types.

## 5. Expected Outputs
Schema field mapping dictionaries in tracehunt/schemas/event.py.

## 6. Verification Criteria
Validate sample Sysmon and Security event payloads against Pydantic event schemas.

## 7. Common Failures & Troubleshooting
Misinterpreting hexadecimal PIDs (e.g. 0x1a4 vs 420); confusing parent and child PIDs.

## 8. Safety & Ethical Considerations
Treat all string fields from Windows logs as untrusted raw input.

## 9. Documentation Updates
Document telemetry coverage and supported Event IDs in README.md.
