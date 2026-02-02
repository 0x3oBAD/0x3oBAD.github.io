---
title: "Cloud Atlas RedOctober Analysis"
description: "Inside Cloud Atlas: From Spear-phishing to C2 — A Code Level Analysis"
date: 2026-2-2
permalink: /posts/cloud-atlas-writeup/
image:
    path: /assets/img/cloud_atlas.png
categories: [Malware Analysis]
tags: [malware-analysis,reverse-engineering,APT,Cloud Atlas,Red October]

---

---
## Cloud Atlas - Red October
Cloud Atlas Red October, First publicly exposed in 2013 by Kaspersky, this operation demonstrated a high level of technical craftsmanship, modular architecture, and meticulous operational discipline, targeting diplomatic, governmental, and research institutions across multiple countries.

The main objective of the attackers was to gather intelligence from the compromised organizations, which included computer systems.

![](/assets/cloud-atlas/kasper_report.png)

This analysis revisits Cloud Atlas from a reverse engineering perspective, following its execution flow from initial infection to final payload deployment and C2 communication. By dissecting its internal logic, configuration handling, and network behavior, this study aims to shed light on how this campaign operated under the hood and why it remains a significant case study in targeted malware research.

---

## Initial Access
Cloud atlas is delivered by spear phishing mail and then exploits the vulnerabilities known `CVE-2009-3129 (MS Excel)`,`CVE-2010-3333 (MS Word)`and`CVE-2012-0158 (MS Word)` that lets it to execute malicious shellcode embedded with document and then continue its infection chain.

![](/assets/cloud-atlas/cloud_atlas_initial_access.png)
*Red October infection chain*

---

## First stage
We have the malicious document and I will ignore the exploit analysis so I am interested only in where is the **shellcode** and what the **shellcode** drops and executes.
![](/assets/cloud-atlas/first_look_cloudAtlas.PNG)
*Document first look*
At first look we have `RTF` format , So I will have a look on the document physical offsets and dump to find anything related to **shellcode** start.
After using `rtfdump` I have noticed there is object called **Reminder** with physical offset `0x6B52` so I started searching from there for **shellcode** or something related to **position-independent code**.
![](/assets/cloud-atlas/shellcode_physical_offset.PNG)
*RTF dump result*
After examining that offset here we go , we have some **NOPs** and valid opcode such as `B9` which equivalent to `mov ecx` and `E2` which `loop` instruction which looping `ecx` times 

![](/assets/cloud-atlas/cloudAtlas_shellcode_start.PNG)
*0x6B52 physical offset dump*

The next step I will disassemble the bytes there making sure to have valid opcodes
![](/assets/cloud-atlas/shellcode_start.png)
*Shellcode start*

Here we have the start of the **shellcode** and **PIC** instructions as well and it seems to be decrypted!

### Shellcode analysis 

So after we find our **shellcode** we need to debug it and decrypt it to discover the expected functionality to resolve its **APIs** dynamically and drop second stage.

![](/assets/cloud-atlas/hashes_to_resolve.PNG)
*Shellcode after decrypting the layer of encryption*

After decryption we have function call `sub_407BD3` and some decrypted data after it , after we have entered the function it accessing `PEB` then loaded modules to get the `kernel32.dll` , and then passed to function with pointer to decrypted data under `sub_407BD3` which seems to **hashes** and it will be resolved to do **shellcode functionality**.

![](/assets/cloud-atlas/loading_PEB_resolve_hashs.png)
*Loading kernel32.dll and resolve hashes*

After that **shellcode** uses `LoadLibraryA` to load the necessary DLLs and resolving its functions.
![](/assets/cloud-atlas/full_resolved_hashes_shellcode.PNG)
*full resolved hashes for shellcode execution*

After that it drops `decoy document` and `VB script` in `Temp path` and execute it for load the second stage.

![](/assets/cloud-atlas/sc_code_VBS.PNG)
*Dropping VB script*

![](/assets/cloud-atlas/sc_decoy_document.PNG)
*Dropping decoy document*

![](/assets/cloud-atlas/decoy_doc.png)
*Decoy document with Russian*

---
### VBS analysis
This VBs script it seems to decrypt and drops other stages , here we have interesting strings such as `ctfmon.dll` and `redtailed` , also large encrypted blob of data `c`. 

![](/assets/cloud-atlas/vbs_encrypted_data.png)

The main function of that script is to achieve **persistence** through registry key `Software\Microsoft\Windows\CurrentVersion\Run` to put itself to run after system reboot and drops the second stage.

![](/assets/cloud-atlas/vbs_crypt_reg.png)

After execution we have `ctfmon.dll` and `redtailed` in `C:\Users\User\AppData\Roaming`

---
## Second stage

Since we have two files dropped the `ctfmon.dll` seems to decrypt or parse `redtailed` so the goal of our analysis to `ctfmon.dll` either looking for decryption or parsing **PE**.

![](/assets/cloud-atlas/ctfmon_sus_pe_parsing.PNG)
*Checking for PE*

As expected we have **PE** validation check for possible **PE parsing**.

![](/assets/cloud-atlas/ctfmon_pe_allocation.png)
*PE parsing function*

I looked around this function to find out if it actually maps `redtailed` but I didn't find anything related so it is going to unpack itself!

---

### Unpacking second stage
So now we are going to unpack `ctfmon.dll` and here we go we have **PE** file.
![](/assets/cloud-atlas/ctfmon_unpacked_pe.PNG)
*unpacked ctfmon.dll*

After unpacking we will return to our task to search about `redtailed` again:)

Here we have file mapping , I believe it will map it then parsing or decrypting

![](/assets/cloud-atlas/unpacked_ctfmon_file_mapping.png)
*Unpacked ctfmon.dll mapping redtailed*

Again , we have PE parsing function in unpacked `ctfmon.dll` so now `redtailed` is another **PE file**

![](/assets/cloud-atlas/unpacked_ctfmon_pe_parsing.PNG)
*unpacked ctfmon.dll PE parsing*

![](/assets/cloud-atlas/unpacked_ctfmon_file_pe.png)
*Parsing PE after file mapping and decryption*

Now we will switch to debugger to dump the contents of decrypted of `redtailed` , the unpacked **ctfmon.dll** is operating on `Windows XP` so keep that in your mind.

![](/assets/cloud-atlas/unpacked_ctfmon_open_redtailed.png)
*ctfmon.dll redtailed mapping*

Now we are sure about **redtailed** mapping then we break after **PE parsing** function to have a clean **PE**.

![](/assets/cloud-atlas/redtailed_decrypted.png)
*redtailed*

---
## C2 configuration extraction

After unpacking **redtailed** , here we have interesting **MPR APIs** for C2 communication and configuration , we have `WNetAddConnection2A` that connects computer to a network resource with **username and password** and also `WNetGetResourceInformationA` that queries info about a network resource and resolves it , which is interesting! , here we have our two entry point for analysis `first` **what is the C2 credentials username and password** , `second` **what is the malware trying to resolve from C2 is another stage ?** 

![](/assets/cloud-atlas/unpacked_redtailed_C2_APIs.png)
*C2 APIs*

![](/assets/cloud-atlas/redtailed_C2_func.png)
*C2 communication function*

---

### Gathering Information

First the malware gather information about the system preparing it for C2 maybe..

![](/assets/cloud-atlas/unpacked_Redtailed_gathering_information.PNG)

----

### PE parsing

![](/assets/cloud-atlas/unpacked_redtailed_pe_parser.PNG)
*Another PE parser:)*

As expected it tries to parse PE , and around it there is heavily crypto functions to decrypts the contents before parsing and after it also! , after successful **PE parsing and decryption** the malware will call the **payload entrypoint**.

![](/assets/cloud-atlas/redtailed_pe_resolving_and_decryption.png)
*PE parsing and decryption*

---

### Configuration decryption 

The malware before parsing and C2 communication decrypts a large blob of data embedded with it , and it seems to be the C2 configuration 

![](/assets/cloud-atlas/decrypting_the_config.png)

![](/assets/cloud-atlas/unpacked_redtailed_decrpted_blob_C2.png)
*C2 cloud server and it's credentials*

Here we go , we have now the C2 server and its credentials . to make sure about it I continued the debugging till to explore what it wants from server.

![](/assets/cloud-atlas/unpacked_redtailed_C2_Get_Resource.png)

here we have the path of required resource , username , password and the cloud server.

The required resource it seems to **PE file** according to this graph of flow of execution.

![](/assets/cloud-atlas/path_of_exection.png)
*Execution flow of redtailed*

---

## Conclusion

The analysis of the Cloud Atlas (Red October) sample highlights why this campaign remains one of the most notable examples of targeted cyber espionage. Its multi-stage architecture, careful use of encryption, and modular design reflect a highly deliberate engineering approach aimed at persistence, stealth, and flexibility. By following the execution flow from the initial loader to the final payload and reconstructing its C2 communication logic, this study demonstrates how technical reverse engineering can provide deep insight into an attacker’s capabilities and operational mindset.

Even though the original C2 infrastructure is no longer active, the artifacts recovered from the sample—its configuration structure, network logic, and internal workflow—remain valuable for understanding both historical and modern threat actor techniques. Cloud Atlas serves as a reminder that well-designed malware is not just about exploiting systems, but about sustained, adaptive intelligence collection

---

## File hashes

|------|-------|
| malicious.doc | 35eb4733093130eb313dc9942372abbb |
| PrgWMW.vbs | f560bc8d6719dcd2b29eeb39317ca517 |
| ctfmon.dll(packed) | 4628082e11c75b078ff0465523598040|
| redtailed(packed) | 514ce567c063e951a578701bb7b0a7f5 |
| ctfmon.dll(unpcked) |4d7658a41418249368c508bc404f7ee9 |
| redtailed.dll(unpacked) | c7a1ecb12b9b876795c822a65228777d |

---





