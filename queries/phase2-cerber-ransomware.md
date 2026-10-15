# Phase 2: Cerber Ransomware (we8105desk to file server)

All searches run against `index=client1` in Splunk BOTS v1.

> **Note:** These queries are transcribed from my original investigation notes and screenshots. I no longer have access to the Splunk environment, so they were not re-run for this write-up. The screenshots in `evidence/` show the original searches and results.

## USB device connected to the workstation
Registry data from `we8105desk` shows a removable drive with the friendly name `MIRANDA_PRI`. This is treated as a **suspected** infection vector; the logs don't tie it to the infection time.

```spl
index=client1 host=we8105desk sourcetype="WinRegistry" friendlyname
| top limit=1 data
```

## Identify the file server
A registry key created on the workstation shows a mounted share on `192.168.250.20` (`fileshare`).

```spl
index=client1 host="we8105desk" sourcetype=WinRegistry fileshare
| head 1
```

## Count PDFs encrypted on the file server
Result: **257** unique `.pdf` files on `we9041srv`.

```spl
index=client1 host=we9041srv app="win:unknown"
| where like(lower(Relative_Target_Name), "%.pdf")
| stats dc(Relative_Target_Name)
```

## Count `.txt` files encrypted on the workstation
Sysmon file-creation events (EventID 2) under the user's profile. Result: **401** unique `.txt` files.

```spl
index=client1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" host="we8105desk"
| rex max_match=1 "<EventID>(?<EventID>\d+)</EventID>"
| where EventID=2
| rex field=_raw "<Data Name='TargetFilename'>(?<TargetFilename>[^<]+)</Data>"
| where like(TargetFilename, "C:\\Users\\bob.smith.WAYNECORPINC\\%.txt")
| stats dc(TargetFilename) as unique_txt_files_encrypted
```

**Total encrypted: 401 + 257 = 658 files.**

---
*Other Phase 2 findings (the malicious URL visited, `mhtr.jpg` download, the `20429.vbs` dropper and `wscript.exe` process chain, the Cerber C2 domain, and the steganography technique) are documented in the report and evidence screenshots.*
