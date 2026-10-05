# Donn Gordon

**Detection Engineering Lead · Cyber Range Engineer · Penetration Testing & Red Teaming · Malware Analysis**

I turn attacker behavior into high-quality detections, and I build the cyber range environments where defenders and attackers train. I love to create and design software, and I write the Python, PowerShell, Bash and Ansible automation that makes security engineering repeatable.

## What I do

- **Detection engineering:** SIEM-integrated detections in Sigma, Splunk Enterprise Security, Microsoft Sentinel, Security Onion and ELK, aligned to MITRE ATT&CK.
- **Cyber range engineering:** enterprise-scale ranges with Active Directory, VMware, KVM and Hyper-V, and centralized telemetry pipelines for SOC training and detection validation.
- **Penetration testing and red teaming:** penetration testing, phishing simulation and adversary emulation (OSCP, eWPTX, CEH).
- **Malware analysis environments:** sandbox labs built with REMnux, FLARE-VM and Cuckoo Sandbox.
- **Software and automation:** tools that deploy ranges, move telemetry and speed up investigations.

## Projects

- [detection-rules](https://github.com/donngordon/detection-rules): original Sigma rules mapped to MITRE ATT&CK.

---

# Detecting Suspicious PowerShell Execution with Sigma

PowerShell is installed on every Windows host, trusted by administrators and heavily used by attackers (MITRE ATT&CK T1059.001). A rule that fires whenever `powershell.exe` runs buries analysts in noise, and a rule that is too narrow misses obfuscated variants. Good PowerShell detection sits between the two.

## Telemetry you need

- **Process creation with command lines:** Sysmon Event ID 1, or Windows Security Event ID 4688 with "Include command line in process creation events" enabled.
- **Script block content:** PowerShell Event ID 4104 (ScriptBlock logging) for rules that inspect what actually ran.
- **Context:** parent process, user and host, to separate administration from attacker behavior.

## Detection approach

I write detections in Sigma so the logic stays portable across SIEMs, then convert them to the backend query language with sigma-cli. For PowerShell I think in three layers:

1. **Command-line flags:** encoded commands, hidden windows, execution policy bypass.
2. **Script block content:** download cradles and in-memory execution patterns.
3. **Context:** unusual parents (Office applications, script hosts) and unusual accounts.

### Example: encoded PowerShell

```yaml
title: Suspicious Encoded PowerShell Command Line
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_flags:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -ec '
  condition: selection_img and selection_flags
falsepositives:
  - Legitimate administration scripts
  - Software deployment and configuration management tools
level: medium
tags:
  - attack.execution
  - attack.t1059.001
```

## Tuning

Administration and deployment tools often use encoded commands too. Expect to exclude known parent processes, service accounts and management hosts before this rule is useful in production, and revisit those exclusions regularly.

## Limitations

- Attackers can rename the binary or use other abbreviations of the encoded-command flag, so this rule is one layer, not full coverage.
- Obfuscation inside the script (string concatenation, variable substitution) needs script block logging to catch.
- Without command-line auditing enabled, the rule has nothing to match, so verify your telemetry before you trust a silent rule.

## Next steps

- Add script block detections for download cradles and in-memory execution.
- Extend coverage to persistence and command-and-control behavior.
- Bring the same approach to cloud and container telemetry.

The rules are in the [detection-rules](https://github.com/donngordon/detection-rules) repository.

## References

- [MITRE ATT&CK T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Sigma rule specification](https://github.com/SigmaHQ/sigma-specification)
