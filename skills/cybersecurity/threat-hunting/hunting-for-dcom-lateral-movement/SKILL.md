---
name: hunting-for-dcom-lateral-movement
description: Hunt for DCOM-based lateral movement by Tespit etme abuse of MMC20.Application, ShellBrowserWindow, and ShellWindows COM objects through Sysmon Event ID 1 (process creation) and Event ID 3 (network
  connection) correlation, WMI event analysis, RPC endpoint mapper traffic on port 135, and DCOM-specific parent-child process relationships.
tags:
- threat-hunting
- DCOM
- WMI
- RPC
- COM-objects
- ShellWindows
- T1021.003
- fetih
- cybersecurity
- MMC20
- lateral-movement
- siber-güvenlik
- Sysmon
- ShellBrowserWindow
triggers:
- alert
- anomali tespit
- authentication
- cloud
- dcom
- endpoint
- exploit
- forensic
- http
- hunting
- lateral
- log
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Hunting for Dcom Lateral Movement


> **Authorized Testing Disclaimer**: The offensive techniques and attack simulations described in bu skill are intended exclusively for authorized penetration testing, red team engagements, purple team exercises, and security research conducted with explicit written permission from the system owner. Unauthorized use of these techniques against systems you do not own or have permission to test is illegal and unethical. Always operate within the scope of your engagement and comply with applicable laws and regulations.

## Genel Bakış

Distributed Component Object Model (DCOM) enables remote execution of COM objects across a network using RPC. Adversaries abuse specific DCOM objects -- MMC20.Application (CLSID {49B2791A-B1AE-4C90-9B8E-E860BA07F889}), ShellBrowserWindow (CLSID {C08AFD90-F2A1-11D1-8455-00A0C91F3880}), and ShellWindows (CLSID {9BA05972-F6A8-11CF-A442-00A0C90A8F39}) -- to execute commands on remote hosts without dropping files, making this a stealthy lateral movement technique mapped to MITRE ATT&CK T1021.003. bu skill provides Tespit strategies using Sysmon telemetry, Windows Security Event correlation, network monitoring, and SIEM Tespit rules to identify DCOM abuse in enterprise environments.

## Ne Zaman Kullanılır

- Proactively hunting for lateral movement in Active Directory environments where DCOM is enabled
- Investigating alerts for suspicious mmc.exe, dllhost.exe, or explorer.exe child process creation on servers
- Building Tespit rules for MITRE ATT&CK T1021.003 (Remote Services: Distributed Component Object Model)
- Correlating Sysmon Event ID 1 (Process Create) and Event ID 3 (Network Connection) to trace DCOM-based command execution chains
- Auditing DCOM exposure across the domain to reduce lateral movement attack surface
- During purple team exercises validating Tespit coverage for DCOM-based techniques

**Kullanma:** as a replacement for EDR-based lateral movement Tespit, without Sysmon or equivalent process telemetry Dağıtılmış on endpoints, or in isolation without correlating network-level and host-level indicators.

## Ön Gereksinimler

- Sysmon Dağıtılmış on endpoints with configuration capturing Event ID 1 (Process Create), Event ID 3 (Network Connection), Event ID 7 (Image Loaded), and Event ID 10 (Process Access)
- Windows Security Event Logs forwarded to SIEM (Event IDs 4624, 4672, 4688)
- SIEM platform (Splunk, Elastic, Microsoft Sentinel) with correlation capability
- Network monitoring for RPC traffic (TCP 135 and dynamic high ports 49152-65535)
- Baseline inventory of legitimate DCOM usage in the environment
- Understanding of MITRE ATT&CK Lateral Movement tactic (TA0008) and T1021.003

## İş Akışı

### Adım 1: Understand DCOM Lateral Movement Attack Vectors

DCOM lateral movement exploits three primary COM objects. Each has distinct forensic artifacts.

**MMC20.Application** -- The attacker instantiates the MMC snap-in remotely and calls `ExecuteShellCommand` to run arbitrary commands on the target. This spawns mmc.exe as a child of svchost.exe (DcomLaunch service) on the target.

**ShellBrowserWindow** -- Uses the `Document.Application.ShellExecute` method to execute commands through an existing explorer.exe process. Unlike MMC20, this does not Şunu oluştur: new process for the COM server itself, making it stealthier.

**ShellWindows** -- Similar to ShellBrowserWindow, it activates within an existing explorer.exe instance and executes child processes from explorer.exe. The absence of a new COM server process makes it harder to tespit etmewithout proper telemetry.

```powershell


```

### Adım 2: Configure Sysmon for DCOM Tespit

```xml
<!-- Sysmon configuration excerpt for DCOM lateral movement Tespit -->
<!-- Add these rules to your existing Sysmon config -->

<Sysmon schemaversion="4.90">
  <EventFiltering>

    <!-- Event ID 1: Process Creation - tespit etmeDCOM-spawned processes -->
    <RuleGroup name="DCOM_ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- MMC20.Application: mmc.exe spawning child processes -->
        <ParentImage condition="end with">mmc.exe</ParentImage>
        <!-- DcomLaunch service spawning COM servers -->
        <ParentCommandLine condition="contains">DcomLaunch</ParentCommandLine>
        <!-- dllhost.exe spawning suspicious children -->
        <ParentImage condition="end with">dllhost.exe</ParentImage>
        <!-- explorer.exe spawning cmd/powershell (ShellWindows/ShellBrowserWindow) -->
        <Rule groupRelation="and">
          <ParentImage condition="end with">explorer.exe</ParentImage>
          <Image condition="end with">cmd.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <ParentImage condition="end with">explorer.exe</ParentImage>
          <Image condition="end with">powershell.exe</Image>
        </Rule>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 3: Network Connection - Track DCOM RPC connections -->
    <RuleGroup name="DCOM_NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- RPC Endpoint Mapper -->
        <DestinationPort condition="is">135</DestinationPort>
        <!-- DCOM processes making network connections -->
        <Image condition="end with">mmc.exe</Image>
        <Image condition="end with">dllhost.exe</Image>
        <!-- svchost.exe DcomLaunch connections -->
        <Rule groupRelation="and">
          <Image condition="end with">svchost.exe</Image>
          <DestinationPort condition="more than">49151</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 7: Image Loaded - DCOM-related DLLs -->
    <RuleGroup name="DCOM_ImageLoaded" groupRelation="or">
      <ImageLoad onmatch="include">
        <ImageLoaded condition="end with">comsvcs.dll</ImageLoaded>
        <ImageLoaded condition="end with">ole32.dll</ImageLoaded>
        <ImageLoaded condition="end with">rpcrt4.dll</ImageLoaded>
      </ImageLoad>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
```

```bash

```

### Adım 3: Build SIEM Detection Rules for DCOM Object Abuse

```yaml
title: DCOM Lateral Movement via MMC20.Application
id: 8a3b5f2e-c1d4-4a9f-b237-1e6f8d2c3a4b
status: stable
description: >
  tespit etme (s) remote instantiation of MMC20.Application DCOM object by monitoring
  for mmc.exe spawned by svchost.exe DcomLaunch service with subsequent child
  process creation, indicating T1021.003 lateral movement.
references:
    - https://attack.mitre.org/techniques/T1021/003/
    - https://www.cybereason.com/blog/dcom-lateral-movement-techniques
    - https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-2-dcom/
logsource:
    category: process_creation
    product: windows
Tespit:
    selection_parent:
        ParentImage|endswith: '\mmc.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\regsvr32.exe'
    filter_legitimate:
        ParentCommandLine|contains:
            - 'devmgmt.msc'
            - 'diskmgmt.msc'
            - 'services.msc'
            - 'compmgmt.msc'
    condition: selection_parent and selection_child and not filter_legitimate
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.003
falsepositives:
    - Legitimate remote MMC administration by authorized IT staff
    - SCCM or other management tools using DCOM for remote management
```

```yaml
title: DCOM Lateral Movement via ShellWindows or ShellBrowserWindow
id: 2f7c9d1e-a8b3-4c5f-9012-3e4d5f6a7b8c
status: stable
description: >
  tespit etme (s) DCOM lateral movement using ShellWindows (CLSID 9BA05972) or
  ShellBrowserWindow (CLSID C08AFD90) by monitoring for explorer.exe spawning
  cmd.exe or powershell.exe on systems where no user is interactively logged on,
  or where the network logon (Type 3) precedes the process creation.
references:
    - https://attack.mitre.org/techniques/T1021/003/
    - https://www.elastic.co/guide/en/security/8.19/incoming-dcom-lateral-movement-with-shellbrowserwindow-or-shellwindows.html
logsource:
    category: process_creation
    product: windows
Tespit:
    selection:
        ParentImage|endswith: '\explorer.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\mshta.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    filter_interactive:
        LogonId: '0x3e7'
    condition: selection and not filter_interactive
level: medium
tags:
    - attack.lateral_movement
    - attack.t1021.003
falsepositives:
    - Users launching command prompts from Explorer context menus
    - Software installers launching child processes from explorer.exe
```

```yaml
title: DCOM Process Inbound RPC Connection Followed by Process Creation
id: 4d9e2f1a-b3c5-4a7f-8901-2c3d4e5f6a7b
status: experimental
description: >
  Correlates Sysmon Event ID 3 (Network Connection) on port 135 with
  subsequent Event ID 1 (Process Create) from DCOM parent processes
  (mmc.exe, dllhost.exe, explorer.exe) within a short time window.
logsource:
    product: windows
    service: sysmon
Tespit:
    network_connection:
        EventID: 3
        DestinationPort: 135
        Initiated: 'false'
    process_creation:
        EventID: 1
        ParentImage|endswith:
            - '\mmc.exe'
            - '\dllhost.exe'
            - '\svchost.exe'
    timeframe: 30s
    condition: network_connection | near process_creation
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.003
```

### Adım 4: Dağıt: Splunk and KQL Tespit Queries

```spl

index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 ParentImage="*\\mmc.exe"
(Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
 OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe")
| eval target_host=ComputerName
| join target_host type=inner
    [search index=wineventlog EventCode=4624 LogonType=3
    | where AuthenticationPackageName="NTLM" OR AuthenticationPackageName="Kerberos"
    | eval target_host=ComputerName
    | rename IpAddress as source_ip, TargetUserName as logon_user
    | fields target_host source_ip logon_user _time]
| where abs(_time - relative_time(now(), "-5m")) < 300
| table _time target_host Image ParentImage CommandLine source_ip logon_user
| sort -_time
```

```spl

index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 ParentImage="*\\explorer.exe"
(Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| eval target_host=ComputerName
| join target_host type=inner
    [search index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
     EventCode=3 DestinationPort=135 Initiated="false"
    | eval target_host=ComputerName
    | rename SourceIp as dcom_source_ip
    | fields target_host dcom_source_ip _time]
| where abs(_time - relative_time(now(), "-2m")) < 120
| stats count values(Image) as child_processes values(CommandLine) as commands
    by target_host dcom_source_ip
| where count > 0
| table target_host dcom_source_ip child_processes commands count
```

```spl

index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 DestinationPort=135 Initiated="false"
| stats dc(SourceIp) as unique_sources count by ComputerName
| where unique_sources > 3 OR count > 10
| sort -unique_sources
| table ComputerName unique_sources count
```

```kql
-- Microsoft Sentinel KQL: DCOM Lateral Movement via MMC20.Application

let dcom_network = SysmonEvent
| where EventID == 3
| where DestinationPort == 135
| where InitiatedConnection == false
| project NetworkTime=TimeGenerated, TargetComputer=Computer,
    SourceIP=SourceIp, DestPort=DestinationPort;

let dcom_process = SysmonEvent
| where EventID == 1
| where ParentImage endswith "\\mmc.exe"
    or ParentImage endswith "\\dllhost.exe"
| where Image endswith "\\cmd.exe"
    or Image endswith "\\powershell.exe"
    or Image endswith "\\pwsh.exe"
    or Image endswith "\\wscript.exe"
    or Image endswith "\\mshta.exe"
| project ProcessTime=TimeGenerated, TargetComputer=Computer,
    ParentImage, Image, CommandLine, User;

dcom_network
| join kind=inner (dcom_process) on TargetComputer
| where abs(datetime_diff('second', NetworkTime, ProcessTime)) < 60
| project NetworkTime, ProcessTime, TargetComputer, SourceIP,
    ParentImage, Image, CommandLine, User
| sort by NetworkTime desc
```

```kql
-- Microsoft Sentinel KQL: ShellWindows DCOM Lateral Movement

SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName in ("NTLM", "Kerberos")
| project LogonTime=TimeGenerated, TargetComputer=Computer,
    SourceIP=IpAddress, LogonUser=TargetUserName
| join kind=inner (
    SysmonEvent
    | where EventID == 1
    | where ParentImage endswith "\\explorer.exe"
    | where Image endswith "\\cmd.exe"
        or Image endswith "\\powershell.exe"
        or Image endswith "\\pwsh.exe"
    | project ProcessTime=TimeGenerated, TargetComputer=Computer,
        Image, CommandLine, User
) on TargetComputer
| where ProcessTime between (LogonTime .. (LogonTime + 2m))
| project LogonTime, ProcessTime, TargetComputer, SourceIP,
    LogonUser, Image, CommandLine
| sort by LogonTime desc
```

### Adım 5: WMI Event Correlation for DCOM Activity

```spl

index=wineventlog source="WinEventLog:Microsoft-Windows-WMI-Activity/Operational"
| where EventCode IN (5857, 5858, 5859, 5860, 5861)
| eval event_type=case(
    EventCode=5857, "WMI Provider Loaded",
    EventCode=5858, "WMI Query Error",
    EventCode=5859, "WMI Provider Event",
    EventCode=5860, "WMI Temporary Event Registration",
    EventCode=5861, "WMI Permanent Event Registration")
| stats count values(event_type) as wmi_events by ComputerName
| where count > 5
| table ComputerName wmi_events count
```

```powershell

Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" -MaxEvents 500 |
    Where-Object {
        $_.Id -in @(5857, 5858, 5860, 5861) -and
        $_.Message -match "DCOM|MMC20|ShellWindows|ShellBrowserWindow"
    } |
    Select-Object TimeCreated, Id,
        @{N='Detail'; E={$_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))}} |
    Format-Table -AutoSize

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath @"
*[System[(EventID=1)]] and
*[EventData[
    (Data[@Name='ParentImage'] and
     (contains(Data[@Name='ParentImage'],'mmc.exe') or
      contains(Data[@Name='ParentImage'],'dllhost.exe')))
]]
"@ -MaxEvents 100 |
    Select-Object TimeCreated,
        @{N='ParentImage'; E={$_.Properties[20].Value}},
        @{N='Image'; E={$_.Properties[4].Value}},
        @{N='CommandLine'; E={$_.Properties[10].Value}},
        @{N='User'; E={$_.Properties[12].Value}} |
    Format-Table -AutoSize
```

### Adım 6: Network-Level DCOM Tespit with Zeek

```bash

cat > /opt/zeek/share/zeek/site/custom-Tespits/dcom-lateral-movement.zeek << 'ZEEKEOF'
@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/dce-rpc

module DCOMLateralMovement;

export {
    redef enum Notice::Type += {
        DCOM_Lateral_Movement_Suspected,
        DCOM_RPC_Scan
    };

    # Threshold for unique targets receiving RPC connections from single source
    const rpc_target_threshold: count = 3 &redef;
    const rpc_time_window: interval = 10min &redef;
}

event zeek_init()
{
    local r1 = SumStats::Reducer(
        $stream="dcom.rpc_targets",
        $apply=set(SumStats::UNIQUE)
    );

    SumStats::create([
        $name="Detect-dcom-lateral",
        $epoch=rpc_time_window,
        $reducers=set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
            return result["dcom.rpc_targets"]$unique + 0.0;
        },
        $threshold=rpc_target_threshold + 0.0,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([
                $note=DCOM_RPC_Scan,
                $msg=fmt("Host %s connected to %d hosts on RPC/135 in %s - possible DCOM lateral movement",
                         key$str, result["dcom.rpc_targets"]$unique, rpc_time_window),
                $identifier=key$str
            ]);
        }
    ]);
}

event connection_state_remove(c: connection)
{
    if ( c$id$resp_p == 135/tcp && c$id$resp_h in Site::local_nets )
    {
        SumStats::observe("dcom.rpc_targets",
            [$str=cat(c$id$orig_h)],
            [$str=cat(c$id$resp_h)]
        );
    }
}
ZEEKEOF

cat /opt/zeek/logs/current/dce_rpc.log | \
  zeek-cut ts id.orig_h id.resp_h endpoint operation | \
  grep -iE "IDispatch|IRemoteActivation|IRemUnknown|IObjectExporter" | \
  sort -t$'\t' -k2 | uniq -c | sort -rn

cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h id.resp_p duration | \
  awk '$4 == 135' | \
  awk '{print $2, "->", $3}' | sort | uniq -c | sort -rn | head -20
```

### Adım 7: DCOM Attack Surface Audit and Hardening

```powershell

Get-CimInstance -ClassName Win32_DCOMApplication |
    Select-Object AppID, Name |
    Sort-Object Name |
    Format-Table -AutoSize

$clsids = @{
    "MMC20.Application"    = "{49B2791A-B1AE-4C90-9B8E-E860BA07F889}"
    "ShellWindows"         = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"
    "ShellBrowserWindow"   = "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}"
    "Excel.Application"    = "{00024500-0000-0000-C000-000000000046}"
    "Outlook.Application"  = "{0006F03A-0000-0000-C000-000000000046}"
}

foreach ($name in $clsids.Keys) {
    $clsid = $clsids[$name]
    $regPath = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
    if (Test-Path $regPath) {
        $launchPermission = (Get-ItemProperty -Path "$regPath" -Name "LaunchPermission" -ErrorAction SilentlyContinue)
        Write-Host "[*] $name ($clsid): $(if ($launchPermission) { 'Custom permissions set' } else { 'DEFAULT permissions (potentially exploitable)' })"
    } else {
        Write-Host "[-] $name ($clsid): Not found on this system"
    }
}

$dcomEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM").EnableDCOM
Write-Host "`n[*] DCOM Enabled: $dcomEnabled"

$remoteLaunch = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "DefaultLaunchPermission" -ErrorAction SilentlyContinue)
Write-Host "[*] Default Launch Permission: $(if ($remoteLaunch) { 'Custom' } else { 'System Default' })"
```

```powershell


#

```

## Key Concepts

| Term | Definition |
|------|------------|
| **DCOM (T1021.003)** | Distributed Component Object Model -- extends COM to allow remote object instantiation and method invocation over RPC, abused for lateral movement |
| **MMC20.Application** | COM object (CLSID {49B2791A-B1AE-4C90-9B8E-E860BA07F889}) controlling MMC snap-ins; `ExecuteShellCommand` method enables remote command execution |
| **ShellWindows** | COM object (CLSID {9BA05972-F6A8-11CF-A442-00A0C90A8F39}) that activates within an existing explorer.exe process, executing commands without creating a new COM server process |
| **ShellBrowserWindow** | COM object (CLSID {C08AFD90-F2A1-11D1-8455-00A0C91F3880}) similar to ShellWindows, uses `Document.Application.ShellExecute` for stealthy command execution |
| **RPC Endpoint Mapper** | Service on TCP port 135 that maps RPC interfaces to dynamic ports; all DCOM communication begins with an endpoint mapper query |
| **Sysmon Event ID 1** | Process Create event capturing parent-child process relationships, command lines, and user context -- critical for identifying DCOM-spawned processes |
| **Sysmon Event ID 3** | Network Connection event capturing source/destination IPs and ports -- used to correlate RPC connections with subsequent process creation |
| **DcomLaunch** | Windows service (svchost.exe -k DcomLaunch) that manages DCOM server process activation; parent process of COM servers spawned via remote DCOM calls |
| **WMI-Activity ETW** | Event Tracing for Windows provider that logs WMI method calls, instance creations, and queries -- provides visibility into DCOM-triggered WMI operations |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Sysmon** | Endpoint telemetry for process creation (EID 1), network connections (EID 3), and image loads (EID 7) essential for DCOM Tespit |
| **Splunk / Elastic SIEM** | Log aggregation and correlation platform for DCOM Tespit rules and threat hunting queries |
| **Microsoft Sentinel** | Cloud SIEM with built-in KQL queries and analytics rules for DCOM lateral movement Tespit |
| **Sigma** | Vendor-agnostic Tespit rule format for portable DCOM Tespit rules |
| **Zeek** | Network security monitor for DCE-RPC protocol analysis and RPC endpoint mapper traffic monitoring |
| **Atomic Red Team** | MITRE ATT&CK test framework with T1021.003 atomics for validating DCOM Tespit coverage |
| **Impacket (dcomexec.py)** | Python-based DCOM execution tool used by attackers and red teamers for testing DCOM lateral movement |
| **CIMSession / PowerShell** | Native Windows tooling for DCOM object instantiation used in both legitimate administration and attacks |

## Common Scenarios

### Scenario 1: MMC20.Application Lateral Movement to File Server

**Context**: A SOC analyst receives an alert for mmc.exe spawning cmd.exe on a file server (10.10.20.50) at 03:22 UTC. No administrator activity is scheduled at this time.

**Approach**:
1. Query Sysmon Event ID 1 on 10.10.20.50: confirm mmc.exe (parent: svchost.exe -k DcomLaunch) spawned cmd.exe with command line `/c net user /domain > C:\temp\users.txt`
2. Query Sysmon Event ID 3 on 10.10.20.50: identify inbound TCP connection on port 135 from 10.10.5.30 at 03:22:01, followed by a high-port connection at 03:22:02
3. Correlate Event ID 4624 on 10.10.20.50: Bul: LogonType 3 from 10.10.5.30 at 03:22:00 with admin credentials
4. Araştır: 10.10.5.30: check for compromise indicators -- Bul: Mimikatz artifacts in memory, evidence of credential dumping at 03:15
5. Trace the attack chain: initial phishing compromise at 02:45, credential theft at 03:15, DCOM lateral movement at 03:22
6. Contain: isolate 10.10.5.30 and 10.10.20.50, force password reset for compromised admin account, block inbound RPC from non-admin subnets

**Pitfalls**:
- Dismissing mmc.exe activity as legitimate MMC administration without checking the parent process and command line
- Not correlating the network logon (4624) with the process creation to the tespit et: true source host
- Failing to Araştır: the source host for initial compromise indicators

### Scenario 2: ShellWindows Stealthy Lateral Movement

**Context**: During a threat hunt, an analyst queries for explorer.exe spawning cmd.exe on domain controllers and Bul:s several instances on DC01 with no interactive logon sessions.

**Approach**:
1. Verify no interactive sessions: query Event ID 4624 LogonType 2 or 10 on DC01 -- none found during the time window
2. Query Sysmon Event ID 1: explorer.exe spawning cmd.exe with encoded PowerShell commands at 14:05, 14:12, and 14:18
3. Decode the PowerShell: reveals reconnaissance commands (Get-ADUser, Get-ADGroup, Get-ADComputer)
4. Query Sysmon Event ID 3: inbound RPC connections from 10.10.3.15 preceding each process creation
5. the tespit et: ShellWindows pattern: no new mmc.exe or dllhost.exe process created -- commands execute through existing explorer.exe, consistent with ShellWindows/ShellBrowserWindow DCOM abuse
6. Araştır: 10.10.3.15: compromised workstation with Cobalt Strike beacon artifacts

**Pitfalls**:
- Missing the attack because ShellWindows does not Şunu oluştur: separate COM server process -- requires monitoring explorer.exe child processes
- Not having Sysmon Event ID 3 configured to capture network connections from explorer.exe
- Filtering out explorer.exe as a legitimate parent process without considering the server context

## Output Format

```
Hunt ID: TH-DCOM-[DATE]-[SEQ]
Alert Severity: High
MITRE Technique: T1021.003 (Remote Services: DCOM)

Source Host: [IP/Hostname of attacker's machine]
Target Host: [IP/Hostname where DCOM executed]
DCOM Object: [MMC20.Application | ShellWindows | ShellBrowserWindow]
CLSID: [COM object class identifier]

Process Chain:
  Parent: [svchost.exe -k DcomLaunch | explorer.exe | mmc.exe]
  Child:  [cmd.exe | powershell.exe | ...]
  Command Line: [Full command executed]

Network Indicators:
  RPC Connection: [Source IP]:port -> [Target IP]:135 at [timestamp]
  DCOM Port: [Source IP]:port -> [Target IP]:[high-port] at [timestamp]

Authentication Context:
  Event 4624: LogonType 3 from [Source IP] at [timestamp]
  Account: [Domain\Username]
  Logon ID: [Logon session identifier]

Risk Assessment: [Critical/High/Medium]
Recommended Action: [Isolate, Araştır: source, reset credentials, restrict DCOM]
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 4d31ae828cc16631
-->

