# Phase 1: Web Server Compromise (imreallynotbatman.com)

All searches run against `index=client1` in Splunk BOTS v1.

> **Note:** These queries are transcribed from my original investigation notes and screenshots. I no longer have access to the Splunk environment, so they were not re-run for this write-up. The screenshots in `evidence/` show the original searches and results.

## Identify the scanning tool
Looked at HTTP headers sent by the scanning IP (40.80.148.42) to the web server (192.168.250.70). The `Acunetix-Product` header shows **WVS/10.0 (Free Edition)**.

```spl
index=client1 imreallynotbatman.com sourcetype="stream:http" src_ip="40.80.148.42" dest_ip="192.168.250.70"
| top limit=20 dest_headers
```

## Find the password that worked
POSTs to the login form that contain a password field, grouped by password. A password appearing more than once stands out as the one reused after the brute force: `batman`.

```spl
index=client1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" form_data="*passwd=*"
| rex field=form_data "passwd=(?<passwd>\w+)"
| stats count by passwd
| where count > 1
| sort -count
```

## Average password length (brute-force tool traffic only)
Excludes the Acunetix scanner so only the Python-based brute force is measured.

```spl
index=client1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" form_data="*username*" form_data="*passwd*" NOT http_user_agent="*Acunetix*"
| rex field=form_data "passwd=(?<passwd>\w+)"
| eval length=len(passwd)
| stats avg(length) as avg_password_length
| eval avg_password_length=round(avg_password_length)
```

## Time between the two `batman` attempts
```spl
index=client1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" form_data="*username*" form_data="*passwd*"
| rex field=form_data "passwd=(?<passwd>\\w+)"
| search passwd=batman
| transaction passwd
| eval dur=round(duration, 2)
| table dur
```

## Count unique passwords tried by the brute-force IP
Result: **412** unique passwords from 23.22.63.114 using a Python user agent.

```spl
index=client1 sourcetype=stream:http http_method=POST dest_ip="192.168.250.70" uri_path="/joomla/administrator/index.php" NOT "Acunetix" http_user_agent="Python*" src_ip=23.22.63.114
| rex field=form_data "passwd=(?<password>\\w+)"
| dedup password
| stats count
```

## Compare passwords against a wordlist lookup
A lookup of Coldplay song titles was used to identify which attempted passwords came from a known list. Result: `yellow`.

```spl
| inputlookup coldplay
```

---
*Other Phase 1 findings (CMS identification, defacement image, malicious FQDN and IP, upload of `3791.exe` and its MD5) are documented in the report and evidence screenshots.*
