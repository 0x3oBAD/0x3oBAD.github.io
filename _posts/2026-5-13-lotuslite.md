---
title: "MustangPanda New Backdoor LotusLite"
description: "Deep Technical Analysis Of LotusLite"
date: 2026-5-13
permalink: /posts/lotuslite-backdoor-writeup/
image:
    path: /assets/img/cover.webp
categories: [Malware Analysis]
tags: [malware-analysis,reverse-engineering,APT]

---
## LotusLite in nutshell
Chinese state-sponsored APT Mustang Panda has added a new undocumented C++ backdoor `LotusLite` to its arsenal targets the financial sectors in  `India` , `South Korea` and `U.S` . The analyzed sample is a fully-featured **Windows backdoor DLL** disguised as a WPS Office component. Upon execution it silently installs itself under `C:\ProgramData\WKwpsOffice2\`, establishes registry-based persistence, and enters a perpetual C2 beacon loop. The operator gains an **interactive reverse shell**, **full filesystem access**, and **file staging capabilities**. The malware employs multiple anti-analysis techniques including **dynamic API resolution**, **runtime string decryption**, **sandbox evasion** via command-line inspection, and masquerading as a legitimate Microsoft runtime library.

---
## Sample Information

| Field | Value |
|---|---|
| **MD5** | `ef5b753e5a2118d18c5e809c3d159a35` |
| **SHA-1** | `eb352c7f82a6987aaa5f3cad51e4c458970f5600` |
| **SHA-256** | `8dd7d6472771db5b82cfc87adcb03b303fcd8f16462700ce6ff63f3d935348d9` |
| **File Type** | `Win32 DLL` |
| **File Size** | `343.00 KB (351,232 bytes)` |
| **Creation Time (UTC)** | `2026-04-27 06:34:37` |
| **First Seen In The Wild (UTC)** | `2026-04-28 12:45:18` |

![](/assets/loutislite/sample_triage.png)
*Figure(1) Sample Triage on VT*

---
## API resolving 
The malware resolves all imports in runtime by decrypting the **function** and **DLL** names with using a two-phase algorithm:
1. **XOR decryption** with a rotating 5-byte key `Credt` 
2. **In-place reversal** of the decrypted result
![](/assets/loutislite/string_decryption.png)
*Figure(2) String Decryption*
then loading the DLL through `LdrLoadDll` function then import the desired function.
![](/assets/loutislite/DLL_loader_funtion.png)
*Figure(3) DLL loader function*

![](/assets/loutislite/API_resolving_scheme.png)
*Figure(4) API resolving scheme*

---
## Evasion
On startup, the malware inspects its own command-line arguments using a dynamically resolved `CommandLineToArgvW`. It compares each argument against a known allowlist stored as a wide-string buffer. If unexpected arguments are present or if the process was launched without the expected `--DMLA` flag it alters its execution path to `ExitProcess`.
![](/assets/loutislite/cmd_sandbox_evasion.png)
*Figure(5) Sandbox Evasion*

---
## Command and control
`LOTUSLITE` communicates exclusively over **HTTPS** on port **443**, using WinINet APIs resolved dynamically at runtime. All traffic is `POST-based`, with the beacon hitting a hardcoded path `/info/faq/v5` on the C2 host.
To blend in with legitimate traffic, every request carries spoofed headers:
> Request: /info/faq/v5 HTTPS  
> Connection: Keep-Alive  
> Host: learn.microsoft.com  
> User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.102 Safari/537.36  
> Referer: https://www.google.com/  
> Cookie: JSESSIONID=x-ms-cpim-geo, mimicking a Microsoft Azure AD session token  
> Connection timeouts set to 2 minutes via InternetSetOptionW

The C2 certificate CN mismatch is silently suppressed via `SECURITY_FLAG_IGNORE_CERT_CN_INVALID`, meaning the C2 infrastructure runs self-signed or mismatched certificates without triggering any WinINet errors.

![](/assets/loutislite/https_func.png)
*Figure(5) LotusLite Command and Control Function*
Inbound command packets are identified by a 4-byte magic header `0xB2EBCFDF`, followed by a `command ID`, `payload length`, and `payload data`.

| Offset | Size    | Field                   |
|--------|---------|-------------------------|
| +0     | 4 bytes | Magic: `0xB2EBCFDF`     |
| +4     | 4 bytes | Command ID              |
| +8     | 4 bytes | Payload Length          |
| +12    | n bytes | Payload Data            |

The beacon interval adapts based on operational state from `20ms` during active shell I/O up to `2000ms` on C2 failure making traffic pattern detection harder than fixed-interval beacons.

The C2 hostname itself is not hardcoded in the binary and is supplied at runtime by the loader, so I have emulated the checks of the paths installed by the loader loads our malicious DLL and got it and unfortunately its dead right now.
![](/assets/loutislite/C2_no_response.png)
*Figure(6) LotusLite C2 Server No Response*

>C2 : 103[.]79[.]77[.]181

![](/assets/loutislite/C2_Triage.png)
*Figure(7) LotusLite C2 VT triage*

---
## LotusLite Backdoor

| ID   | Name  | Description |
|------|------------------|-------------|
| `0x01` | `CMD_EXEC_CMD` | Executes a shell command via the pipe-backed `cmd.exe` process.Takes a string payload, writes it to the shell stdin pipe using `WriteFile`, and sets the re-poll delay to `60ms (0x3C)`. |
| `0x03` | `CMD_LIST_DIR` | Lists a directory. Takes a path string and calls `sub_10003440`, which performs `FindFirstFileA` / `FindNextFileA` on `path\*`, builds entries in the format `name\|FILE\|size\n` or `name\|DIR\|size\n`, then sends the result back via C2. |
| `0x06` | `CMD_RESET_BEACON` | Resets the beacon flag, forcing the next loop iteration to resend the initial host information beacon and re-register with the C2 server. |
| `0x0A` | `CMD_SPAWN_SHELL` | Creates anonymous `stdin/stdout` pipes and spawn a hidden `cmd.exe` process with redirected handles. Also starts a reader thread for shell output. One-shot behavior: ignored if the shell is already active. |
| `0x0B` | `CMD_KILL_SHELL` |  Terminates the `cmd.exe` process via `TerminateProcess`, close all pipe handles, and clear the shell-active flag. |
| `0x0D` | `CMD_CREATE_FILE` | Takes a filename string and attempts up to five times to create the file using `fopen(name, "wb")` with `60ms` retry delays, then immediately closes it with `fclose`, resulting in an empty file creation. |
| `0x0E` | `CMD_WRITE_FILE` | Accepts a payload formatted as `filename\0data`. Splits the buffer at the null byte, opens the target file in append mode (`"ab"`) with up to five retries, and writes the supplied data blob using `fwrite`. Used for dropping or appending files to disk. |
| `0x0F` | `CMD_PING / CHECKIN` | Sends the string `"OK"` back to the C2 server as a `keepalive/check-in` response. |

---
## Persistence 
>HKCU\Software\Microsoft\Windows\CurrentVersion\Run
> "AwpOn" = "C:\ProgramData\WKwpsOffice2\WKwpsOffice.exe" --DMLA

---
## Key Observation
Based on [VT triage](https://www.virustotal.com/gui/ip-address/103.79.77.181/details) of C2 about the `last HTTPS certificate` , The certificate was issued `2026-03-12` and the **Venezuela-themed** campaign started **January 2026** , meaning this cert was provisioned specifically for the campaign infrastructure. The `India/South Korea` campaign `March 2026` timing aligns perfectly with this cert issuance date, suggesting this IP is part of the `LOTUSLITE v1.1` wave targeting **Indian banks** and **Korean diplomats**, not the original **Venezuela campaign**.
That date correlation alone narrows the infrastructure cluster significantly , any other `MyLocalManager` certs issued in the same `March 2026` window are almost certainly the same operator spinning up parallel C2 nodes.

---
## IOCs

| Category | Summary |
|---|---|
| **File System** | Drops files into `C:\ProgramData\WKwpsOffice2\`, including `WKwpsOffice.exe` and a masqueraded DLL `Microsoft.WindowsAppRuntime.Bootstrap.dll`. |
| **Registry Persistence** | Creates the `AwpOn` Run key under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` to launch `WKwpsOffice.exe --DMLA` at logon. |
| **Process Behavior** | Spawns a hidden `cmd.exe` process using anonymous pipes for remote shell interaction and executes with the `--DMLA` argument. |
| **Network Activity** | Uses HTTPS-based beaconing with a custom binary protocol identified by magic value `0xB2EBCFDF`, with adaptive polling intervals between `20ms` and `2000ms`. |
| **Host Discovery** | Initial beacon includes basic victim identification data such as computer name and username. |

---
## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Initial Access** | Phishing / Malicious File | `T1566.001` | Fake PDF lure with corrupted file error |
| **Execution** | User Execution: Malicious File | `T1204.002` | Victim opens disguised PDF/EXE |
| **Persistence** | Registry Run Keys / Startup Folder | `T1547.001` | `HKCU\...\Run` → `AwpOn` key |
| **Defense Evasion** | Obfuscated Files or Information | `T1027` | XOR + reverse string encryption |
| **Defense Evasion** | Dynamic-link Library Injection | `T1055` | Delivered as DLL |
| **Defense Evasion** | Masquerading | `T1036.005` | Drops `Microsoft.WindowsAppRuntime.Bootstrap.dll` |
| **Defense Evasion** | Virtualization/Sandbox Evasion | `T1497.001` | Command-line argument inspection |
| **Defense Evasion** | Indirect Command Execution | `T1202` | API resolution hides imports |
| **Discovery** | System Information Discovery | `T1082` | Collects computer name and username |
| **Discovery** | File and Directory Discovery | `T1083` | `CMD_LIST_DIR` via `FindFirstFile` |
| **Command & Control** | Application Layer Protocol: Web Protocols | `T1071.001` | HTTP-based C2 beacon |
| **Command & Control** | Data Encoding / Custom Protocol | `T1132` | Binary packet format with magic `0xB2EBCFDF` |
| **Execution** | Command and Scripting Interpreter: Windows Command Shell | `T1059.003` | Hidden `cmd.exe` shell with pipe I/O |
| **Collection / Exfiltration** | Data from Local System | `T1005` | Directory listing and shell-based file access |
| **Command & Control** | Ingress Tool Transfer | `T1105` | `CMD_WRITE_FILE` stages additional payloads |

---
## References

1. Acronis TRU. *LOTUSLITE: Targeted Espionage Leveraging Geopolitical Themes*.  
   [Acronis TRU Report](https://www.acronis.com/en/tru/posts/lotuslite-targeted-espionage-leveraging-geopolitical-themes/#-m_BvsUlu9)

2. The Hacker News. *LOTUSLITE Backdoor Targets U.S. Policy Organizations*.  
   [The Hacker News Coverage](https://thehackernews.com/2026/01/lotuslite-backdoor-targets-us-policy.html)

3. ThreadLinqs Intelligence. *TL-2026-0430*.  
   [ThreadLinqs Intel Report](https://intel.threadlinqs.com/#TL-2026-0430)

4. SecureBlink. *Mustang Panda Strikes India and South Korea with Updated LOTUSLITE Backdoor in Espionage Campaign*.  
   [SecureBlink Analysis](https://www.secureblink.com/cyber-security-news/mustang-panda-strikes-india-and-south-korea-with-updated-lotuslite-backdoor-in-espionage-campaign)

5. FarghlyMal. *LOTUSLITE Research Notes and Findings*.  
   [FarghlyMal on X](https://x.com/FarghlyMal/status/2052383177700737465?s=20)
