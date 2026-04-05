---
title: "Payload Threat Actor Ransomware"
description: "Deep Technical Analysis Of Payload Ransomware"
date: 2026-4-5
permalink: /posts/payload-ransomware-writeup/
image:
    path: /assets/img/payload_post.png
categories: [Malware Analysis]
tags: [malware-analysis,reverse-engineering,ransomware,payload]

---

## Payload Threat Actor
The current information about this new threat actor in the wild till this moment is little , but according to [Ahmed Elessaway](https://www.linkedin.com/in/ahmedelessaway/) , It is active since  **17-02-2026** and till this moment has targets between `United States` , `Philippines` , `Mexico` , `United Kingdom` and `Egypt` , and it reached 26 victims.

<details>
  <summary>Victims</summary>

    <div class="scroll-box">
        <pre>
United Finance Egypt
Tscherne Consulting Steuerberatung GmbH
SAYEGH
NKAR Travels & Tours
Q2 Artificial Lift Services
Don-Nan
A A Al Moosa Enterprises (ARENCO Group)
carlysle.net
Vancompare Insurance
iGLS
HOPPECKE Singapore
TS Lines Philippines
Lucky Innovative Manufacturing Corporation
Notaría 89
Royal Bahrain Hospital
J.T. Pack of Foods
Grid Fine Finishes
Alcoholes Finos Dominicanos
In.Sa.Cor
Easy Servizi
Thai Solar Energy Public
United Limsun International Trading
Tyler Media
Río Grande (Puerto Rico)
sodic.com
Almacenes Distribuidores de la Frontera
    </pre>
  </div>
</details>

---
## Sample information

| Field | Value |
|-------|-------|
| **File name** | `locker_esxi.elf` |
| **File format** | `ELF64 Linux x86-64` |
| **File size** | `0x9BE0` (stripped on disk, `0x2097A8` mapped) |
| **MD5** | `f91cbdd91e2daab31b715ce3501f5ea0` |
| **SHA1** | `0252819a4960c56c28b3f3b27bf91218ffed223a` |
| **SHA256** | `bed8d1752a12e5681412efbb8283910857f7c5c431c2d73f9bbc5b379047a316` |

---
## Executive Summary
`locker_esxi.elf` is a 64-bit Linux ELF ransomware binary targeting **VMware ESXi hypervisor environments** . The sample combines a robust cryptographic scheme `Curve25519 ECDH`and `ChaCha20` with ESXi-specific VM enumeration via the **vmInventory.xml** inventory file, graceful shutdown of running VMs before encryption, and a **multi-threaded file encryption** pipeline scaled to available CPU cores. The ransom note is delivered inside ESXi's own web UI `welcome.txt`, replacing the host management interface greeting.

---
## String Decryption
The binary embeds its configuration as `RC4-encrypted` and `base64-encoded` blobs in the `.rodata` section. The RC4 key is the three-byte **FBI**. All sensitive **strings** , **file paths** , **error messages** and **shell commands** are decrypted at runtime through `mw_w_RC4()`.

![](/assets/payload/RC4_function.png)
*Figure(1) mw_w_RC4() Decryption Function*

The python decryption script below to decrypt data blobs in place in IDA to make the analysis more easier.
```python
import idc
import idaapi

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    result = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


RC4_KEY = b"FBI"

BLOBS = [
    (0x6093F0, 0x12),
    (0x6092A0,   33),
    (0x609288,   13),
    (0x609260,   14),
    (0x60925A,    5),
    (0x609250,   10),
    (0x609270,   18),
    (0x609300,   34),
    (0x609380,   43),
    (0x609330,   22),
    (0x609350,   28),
    (0x609220,   44),
    (0x6092D0,   30),
    (0x6093D0,   31),
    (0x6093B0,   20),
]


def patch_blob(ea: int, plaintext: bytes) -> None:
    for offset, byte in enumerate(plaintext):
        idc.patch_byte(ea + offset, byte)
    idc.patch_byte(ea + len(plaintext), 0)


def make_string(ea: int, length: int) -> None:
    idaapi.del_items(ea, idaapi.DELIT_SIMPLE, length + 1)
    idc.create_strlit(ea, ea + length + 1)


def main():
    for ea, size in BLOBS:
        data = idc.get_bytes(ea, size)
        if data is None:
            continue
        plaintext = rc4(RC4_KEY, data)
        patch_blob(ea, plaintext)
        make_string(ea, size)


if __name__ == "__main__":
    main()
```
**Decrypted strings**:
<details>
  <summary>Show List</summary>

    <div class="scroll-box">
        <pre>
set_key(): failed!
[!] base64 pubkey decode failed
[!] invalid key size
vim-cmd vmsvc/power.off %d > /dev/null 2>&1
vm=%d successful turned off!
can't turn off vmid=%d
decode_base64(): failed to decode!
set_note(): failed to open: %s
/etc/vmware/hostd/vmInventory.xml
//ConfigEntry
xmlReadFile failed
no ConfigEntry
bjID
vmcfgPath
/usr/lib/vmware/hostd/docroot/ui/welcome.txt
    </pre>
  </div>
</details>

---

## Technical Analysis

### Anti-Analysis & Defense Evasion
Malware immediately at beginning checks if debugger attached to the process by opening **/proc/self/status** and reads lines until it finds `TracerPid:`, if the integer following that field is non-zero so debugger is attached , execution branches to delete itself.

![](/assets/payload/check_debugger.png)
*Figure(2) Malware checking for debugger*

---
### Cryptographic Scheme
The cryptographic scheme takes stages before doing the actual encryption such as **encryption public key extraction** , **gathering CPU capabilities** , **encryption routine selection** , **thread-pool initialization** and finally **multi-thread encryption job**.

---
#### Public Key extraction 
The malware encodes its public key via **Base-64** encoding shown in figure below , which reveling the public encryption key is `3E67A9F94526785C31C543BE3F4DC7039E7C3F764F65637C6C22B85F3357B575`.
![](/assets/payload/public_key_generation.png)
*Figure(3) Public Key Extraction*

---
#### Gathering CPU Capabilities
The malware wants to run **ChaCha20** as fast as possible, so before any encryption happens it probes the CPU for SIMD capabilities and stores a function pointer to the fastest available implementation. Every subsequent file encryption call goes through that pointer without re-checking.
![](/assets/payload/gathering_CPU_inforamtion.png)
*Figure(4) Gathering CPU Capabilities*
The function  queries processor feature flags via `CPUID` and `XGETBV`:
- Checks **SSE2 support** via `EDX bit 26`.
- Checks **AVX support** via `ECX bits 28/27`.
- Uses `XGETBV` to confirm OS-level AVX state (XSAVE enabled state validation).
- Queries extended features `CPUID leaf 7` to detect **AVX2 support (EBX bit 5)**.

The resulting capability mask is built as:
- `bit 0` **value 0** so SSE2 available.
- `bit 1` **value 1** so AVX usable.
- `bit 2` **value 4** so AVX2 available.
This behavior is consistent with performance-aware malware or protected loaders that adapt cryptographic implementations based on host hardware capabilities.

---
#### Encryption Routine Variants
Based on the CPU capabilities it decides between which routine will handle the encryption logic.
![](/assets/payload/routine_selection.png)
*Figure(5) Encryption routine selection*

**mw_chacha20_scalar**
- **Pure scalar implementation** using 32-bit general-purpose registers (`EAX`, `EBX`, `ECX`, etc.)
- Entire ChaCha20 state maintained as **individual integers** (heavily stack-spilled).
- Rotations implemented manually via `__ROL4__` (shift + OR).
- Processes **1 block (64 bytes) per iteration**.
- Block counter increments by **+1**.
- Simple control flow:
  - Single loop of **10 double-rounds**.
  - Followed by a separate **add-back phase**.
- XOR with plaintext performed **4 bytes at a time**.
- Most **portable but least performant** variant.

**mw_chacha20_sse2**
- Uses **128-bit XMM registers** with VEX-encoded SSE instructions:`vpaddd`, `vpxor`, `vpshufd`, `vpslld`, `vpsrld`.
- Implements **4-way parallelism** each XMM lane represents one block and processes **4 blocks simultaneously**.
- Counter initialization: uses `vpaddq` with precomputed constants to generate **4 parallel counters**.
- Block counter increments by **+4 per iteration**.
- Rotation strategy:
  - Bit rotations via shift+OR.
  - Lane permutations via `vpshufd` (shuffles `0x93`, `0x4E`, `0x39`).
- Output: XOR and writes using XMM registers **16 bytes per store**.
- Loop structure:
  - Outer loop **256-byte aligned chunks (4×64)**.
  - Tail loop remaining 64-byte blocks.
  - Sub-64-byte remainder handled via **stack buffer staging**.

**mw_chacha20_avx2**
- Fully utilizes **256-bit YMM registers**.
- Implements **8-way parallelism** each YMM lane holds one word across **8 blocks**.
- Setup phase:`vbroadcasti128` used to duplicate key/state across YMM lanes.
- Advanced data movement:`vperm2i128` enables **cross-lane shuffling** (critical for 8-block transposition).
- Block counter increments by **+8 per iteration**.
- Rotation optimization: uses `vpshufb` with precomputed masks which **faster than shift+OR**.
- Output: writes **32 bytes per store** (double SSE2 throughput).
- Loop hierarchy:
  - Main loop **512-byte aligned chunks (8×64)**
  - Secondary loop **128-byte tail**
  - Final stage **fine-grained remainder handling** (branching per 32-byte boundary)

And the figure below explains the stages of every routine
<figure style="text-align: center;">
  {% include chacha20_three_variants.svg %}
  <figcaption><em>Figure(6) ChaCha20 Three Variants</em></figcaption>
</figure>
---
#### Thread Pool Execution
The sample initializes a multi-threaded processing pipeline by creating a **thread pool sized at 2× the number of CPU cores**, indicating intent for high-throughput file operations.

It accepts an optional command-line exclusion list `(-i)`, allowing specific ports to be skipped during execution suggesting operator-controlled targeting or selective encryption.

The malware then accesses a VMware ESXi configuration file `(/etc/vmware/hostd/vmInventory.xml)`, with both the file path and `XPath query (//configentry)` RC4-obfuscated , It parses `<configentry>` nodes to extract **port identifiers** (used as directory references)
**datastore paths**(VM storage locations).

The malware then iterates over collected directories and:
- Enumerates files within each directory.
- Skips files already marked as encrypted (**suffix .xx0001**).
- Submits remaining files as jobs to the thread pool for encryption via `mw_encrypt_file`.
![](/assets/payload/thread_pool_add_job.png)
*Figure(7) Malware encrypts files and suffix .xx0001*

Each worker thread on startup calls `prctl(PR_SET_NAME, "FBIthread-pool-%d")` — the thread name string `FBIthread-pool-%d` is embedded in plaintext and is a notable forensic indicator. On wakeup, a thread dequeues a job, executes it as `job->fn(job->arg)`, frees the job struct, and decrements the active-job counter. If the active count drops to zero, a `pthread_cond_signal` is fired to unblock any waiting caller of threadpool wait.

#### Encryption Routine
The function implements a targeted, in-place ransomware encryption workflow optimized for `ESXi/VMware environments`. It exclusively processes files larger than **5 GB**, effectively filtering for virtual disk images such as **VMDK** while ignoring smaller files, indicating deliberate high-value targeting.

Each file undergoes a per-file `Curve25519 ECDH key exchange`, generating a unique ephemeral key pair and deriving a ChaCha20 encryption key from a decoded attacker public key. This ensures strong cryptographic isolation, preventing decryption without attacker-controlled material.

Encryption is performed partially across 5 segments, each up to **1 GB**, using a 1 MB sliding buffer and executed in-place (no temporary files). The ChaCha20 keystream is synchronized with file offsets, enabling deterministic decryption while significantly reducing processing time—typical optimizing for speed on large datasets.
![](/assets/payload/encryption_routine.png)
*Figure(8) Encryption routine*

Post-encryption, the malware appends a **56-byte footer** containing the ephemeral public key, lightly obfuscated using RC4 3-byte key`(“FBI”)`. This serves as metadata for decryption while providing minimal resistance to static extraction. Sensitive key material is explicitly wiped from memory, reflecting anti-forensic intent.

![](/assets/payload/RC4_footer.png)
*Figure(9) Metadata For Decryption*
## Ransom Note 
The ransom note inside **ESXi's** own web UI `welcome.txt`, replacing the host management interface greeting.
```
Welcome to Payload!

The next 72 hours will determine certain factors in the life of your company: 
the publication of the file tree, which we have done safely and unnoticed by all of you, 
and the publication of your company's full name on our luxurious blog.
NONE of this will happen if you contact us within this time frame and our negotiations are favorable.

We are giving you 240 hours to:
1. familiarize yourself with our terms and conditions,
2. begin negotiations with us,
3. and successfully conclude them.
The timer may be extended if we deem it necessary (only in the upward direction).
Once the timer expires, all your information will be posted on our blog.

ATTENTION!
Contacting authorities, recovery agencies, etc. WILL NOT HELP YOU!
At best, you will waste your money and lose some of your files, which they will carefully take to restore!
You should also NOT turn off, restart, or put your computer to sleep.
In the future, such mistakes can make the situation more expensive and the files will not be restored!
We DO NOT recommend doing anything with the files, as this will make it difficult to recover them later!

When contacting us:
you can request up to 3 files from the file tree, 
you can request up to 3 encrypted files up to 15 megabytes 
so that we can decrypt them and you understand that we can do it.

First, you should install Tor Browser:
1. Open: https://www.torproject.org/download
2. Choose your OS and select it
3. Run installer
4. Enjoy!

In countries where tor is prohibited, we recommend using bridges, 
which you can take: https://bridges.torproject.org/

You can read:
[NOPE 3eb] (Tor)

To start negotiations, go to [NOPE] and login:
User: [snip]
Password: [snip]

Your ID to verify: [snip]
```
---
## YARA Rule 
```
rule payload_ransomware
{
    meta:
        description      = "Payload Ransomware "
        author           = "Abdullah Islam @0x3oBAD"
        date             = "2026-04-05"
        md5              = "f91cbdd91e2daab31b715ce3501f5ea0"
        sha256           = "bed8d1752a12e5681412efbb8283910857f7c5c431c2d73f9bbc5b379047a316"
        malware_family   = "ESXi Ransomware Locker"
        target_platform  = "Linux / VMware ESXi"

    strings:
        $pubkey_1        = "TnJqU2F5RFFYREpPTURkUGx5Q3NMem0yNlZKM0s1aks=" ascii
        $pubkey_2        = "Pmep+UUmeFwxxUO+P03HA558P3ZPZWN8bCK4XzNXtXU=" ascii
        $pubkey_head     = "W2M6q8YwDKCcSvBj7YRjVNtSI/PO22G+" ascii

        $ext             = ".xx0001" ascii nocase
        $thread_name     = "FBIthread-pool-%d" ascii

        $thpool_1        = "thpool_init(): Could not allocate memory for thread pool" ascii
        $thpool_2        = "thpool_init(): Could not allocate memory for threads" ascii
        $thpool_3        = "thpool_init(): Could not allocate memory for job queue" ascii
        $thpool_4        = "thpool_add_work(): Could not allocate memory for new job" ascii
        $thpool_5        = "thread_do(): cannot handle SIGUSR1" ascii
        $thpool_6        = "bsem_init(): Binary semaphore can take only values 1 or 0" ascii

        $vim_cmd         = "vim-cmd vmsvc/power.off %d > /dev/null 2>&1" ascii
        $esxi_inventory  = "/etc/vmware/hostd/vmInventory.xml" ascii
        $esxi_note       = "/usr/lib/vmware/hostd/docroot/ui/welcome.txt" ascii
        $xpath_query     = "//ConfigEntry" ascii
        $vmx_field       = "vmxCfgPath" ascii

        $proc_status     = "/proc/self/status" ascii
        $tracer_field    = "TracerPid:" ascii
        $proc_exe        = "/proc/self/exe" ascii

        $key_err_1       = "[!] invalid key size" ascii
        $key_err_2       = "[!] base64 pubkey decode failed" ascii

        $libxml2         = "libxml2.so.2" ascii
        $urandom         = "/dev/urandom" ascii
        $b64_alpha       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii

        $footer_magic    = { 70 61 79 6C 6F 61 64 00 }

    condition:
        (
            uint32(0) == 0x464C457F
            and uint8(4) == 2
            and uint8(5) == 1
            and uint16(0x12) == 0x3E
            and (
                (
                    filesize == 39904
                    and all of ($pubkey_1, $pubkey_2, $pubkey_head)
                )
                or
                (
                    $vim_cmd
                    and $esxi_inventory
                    and (
                        #ext + #thread_name + #thpool_1 + #thpool_2 +
                        #thpool_3 + #thpool_4 + #thpool_5 + #thpool_6 +
                        #vmx_field + #xpath_query + #esxi_note +
                        #key_err_1 + #key_err_2 + #proc_exe +
                        #urandom + #libxml2 >= 6
                    )
                )
                or
                (
                    $thpool_1
                    and $thpool_6
                    and $vim_cmd
                    and 3 of ($libxml2, $urandom, $tracer_field, $b64_alpha, $xpath_query)
                )
            )
        )
        or
        (
            $footer_magic at (filesize - 56 + 24)
        )
}
```
---
## Conclusion
`locker_esxi.elf` is a targeted **ESXi ransomware** focused on encrypting large VM disk files **(>5 GB)** for maximum impact. It uses `Curve25519 + ChaCha20` with per-file keys, ensuring strong cryptographic isolation. The malware leverages multi-threading and SIMD optimizations to accelerate encryption across systems. It demonstrates environment awareness by parsing VMware configs and shutting down VMs before encryption. Overall, it is a highly efficient, enterprise-focused ransomware designed for rapid disruption of virtualized infrastructure.