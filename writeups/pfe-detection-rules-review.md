# Write-up · A senior-style review of my final-year SOC lab detection rules

Reviewed 16 Nov 2026 · Suricata 6.0.4 · Wazuh 4.11.2 · Lab results only, not production

## Why this page exists

My final-year project is a small SOC lab. Before I show its detection rules in a portfolio, I wanted them reviewed the way a senior detection engineer would review a junior's work: what each rule really detects, where it is wrong, and what it misses.

I ran the review with an AI assistant (Claude Code) in the role of the senior reviewer. It read my real rule files and my lab logs. It did not run anything in the lab. The rules, the lab and the mistakes are mine.

The lab in one paragraph: an isolated VMware network with three VMs. An attacker VM (Kali) attacks a victim VM that runs a deliberately vulnerable web app. A sensor VM runs Suricata, which watches the network, and Wazuh, which turns Suricata alerts into SIEM alerts. n8n forwards those alerts to TheHive as cases. I ran 7 attack scenarios. No machine learning was built.

**Short version**

- Each of the 7 rules fired at least once in the lab session where I ran the 7 attacks. That is the only thing I tested: not how often a rule fires, not what else makes it fire, not what it misses.
- Every rule alerts on each matching packet, request or query, with no grouping. One test session produced 3,504 alerts from these 7 rules.
- Most rules match the default fingerprint of the tool I used, and the severity levels do not match how sure each rule is.

## What was reviewed

| File | What it holds | Rule IDs |
|---|---|---|
| `configs/phase2/local.rules` | 7 custom Suricata rules | SID 9000001 to 9000007 |
| `configs/phase3/local_rules.xml` | 7 custom Wazuh rules, one per Suricata SID | 100001 to 100007 |
| `configs/phase4/wazuh-integration-block.xml` | Not a rule. The filter that forwards Wazuh alerts to n8n (level 7 or higher, group `pfe_custom`) | none |

The original files were not changed. Every improved rule on this page is a proposal.

### What my own log says

Alerts per rule in the Wazuh validation log I saved for one test session:

| Scenario | Suricata SID | Wazuh rule | Alerts in that session |
|---|---|---|---|
| SYN port scan | 9000001 | 100001 | 1,732 |
| Nmap script scan | 9000002 | 100002 | 26 |
| SSH brute force | 9000003 | 100003 | 19 |
| Directory brute force | 9000004 | 100004 | 1,619 |
| SQL injection | 9000005 | 100005 | 2 |
| Reverse shell | 9000006 | 100006 | 97 |
| DNS exfiltration | 9000007 | 100007 | 9 |

The log does not say how many times each attack was run, or which attack caused which alert. So these are numbers per session, not per attack.

## How to read the tables

- **Severity** is Low, Medium, High or Critical, with the Wazuh level (0 to 15) I would set.
- **False positives** and **gaps** come from reading the rule logic. The lab has three VMs and no normal user traffic, so none of this was measured.
- Gaps are kept at a high level on purpose.
- In test commands, `<victim>` stands for the victim VM's address.

## Suricata rules

### SID 9000001 · SYN port scan

```text
alert tcp any any -> $HOME_NET any (msg:"PFE RECON Nmap SYN port scan detected"; flags:S; detection_filter:track by_src, count 20, seconds 10; classtype:attempted-recon; sid:9000001; rev:1; metadata:pfe-mitre T1046;)
```

| Question | Finding |
|---|---|
| What it detects | More than 20 TCP packets with only the SYN flag, from one source to any lab address, in 10 seconds. It counts packets, not different ports or hosts, so it measures connection rate. Nothing in it is specific to Nmap. After the threshold it alerts on every further packet. |
| MITRE ATT&CK | T1046 Network Service Discovery. Correct for a scan that comes from inside the same network. |
| Likely false positives | Any busy client: a script or browser opening many connections, monitoring and health checks, backup jobs, an approved vulnerability scanner, many users behind one shared address. |
| Detection gaps | Slow scans that stay under the rate. Scans of only a few ports. Scan types that do not use SYN packets. Scans spread over several sources. |
| Severity I should assign | Low (Wazuh 6). A scan on its own should be logged, not turned into a case. Today it is 7. |
| How I would test it | Positive: `sudo nmap -sS -n <victim>`, then count the alerts. I expect one per time window after the fix, not hundreds. Negative: 30 quick `curl` requests to the victim's web server. Today this fires and is called an Nmap scan. Variant: scan three ports only, then run a slow scan, and write down that both are missed. |

### SID 9000002 · Nmap script scan

```text
alert http any any -> $HOME_NET any (msg:"PFE RECON Nmap NSE user-agent detected"; http.user_agent; content:"Nmap Scripting Engine"; nocase; classtype:attempted-recon; sid:9000002; rev:1; metadata:pfe-mitre T1595;)
```

| Question | Finding |
|---|---|
| What it detects | HTTP requests whose User-Agent holds the default text of the Nmap Scripting Engine. |
| MITRE ATT&CK | T1046 Network Service Discovery, to match SID 9000001: same tool, same step of the attack. My file says T1595 Active Scanning, which is the same activity seen from outside the network. Either can be defended, but the two Nmap rules should agree. If the scripts are vulnerability checks, T1595.002 Vulnerability Scanning is closer. |
| Likely false positives | Few. An admin or a security team running Nmap on purpose. |
| Detection gaps | The User-Agent is a setting the scanner controls. HTTPS is not inspected. It only fires when a web service is open and the HTTP scripts run, so a version scan of SSH alone never triggers it. |
| Severity I should assign | Low (Wazuh 6). I can be sure the tool is Nmap, but the impact is low. Today it is 7. |
| How I would test it | Positive: `sudo nmap -sC -p 80 <victim>`. Negative: a version scan of the SSH port only, where no alert is expected. Variant: the same script scan with a non-default User-Agent, and record the miss. ET Open already has this signature (SID 2009358), so my rule repeats it. |

### SID 9000003 · SSH brute force

```text
alert tcp any any -> $HOME_NET 22 (msg:"PFE INTRUSION SSH brute-force attempt"; flags:S; detection_filter:track by_src, count 5, seconds 60; classtype:attempted-user; sid:9000003; rev:1; metadata:pfe-mitre T1110;)
```

| Question | Finding |
|---|---|
| What it detects | More than 5 SYN packets to port 22 from one source in 60 seconds, to any lab address. It is a connection-rate rule. SSH is encrypted, so it cannot see whether a login failed or worked. |
| MITRE ATT&CK | T1110.001 Brute Force: Password Guessing. My file uses the parent, T1110. |
| Likely false positives | Automation that opens many SSH sessions: configuration management, deploy scripts, backups, monitoring checks, a jump host. An admin who connects to six servers in a minute also fires it, because the count is per source across all destinations. A sweep of port 22 across the subnet fires it too and is wrongly called brute force. |
| Detection gaps | Slow guessing under the rate. Several guesses inside one connection. SSH on another port. Many sources. The biggest one: the rule has no idea whether the attacker got in. |
| Severity I should assign | Medium (Wazuh 8) on its own. High (10 to 12) only when the victim's own SSH log confirms repeated failures. Critical if a successful login follows. Today it is 10. |
| How I would test it | Positive: a password-guessing run with a short wordlist and a few parallel tasks. Negative: six normal key-based logins in one minute. It fires, which shows the false positive. Variant: one attempt every 15 seconds, which should be missed. Cross-check: during the same run, look in Wazuh for the built-in sshd rules (the 5700 series) coming from the victim's agent. |

### SID 9000004 · Directory brute force

```text
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"PFE WEB HTTP directory bruteforce - gobuster user-agent"; http.user_agent; content:"gobuster"; nocase; classtype:web-application-attack; sid:9000004; rev:1; metadata:pfe-mitre T1595.003;)
```

| Question | Finding |
|---|---|
| What it detects | HTTP requests to the ports in `$HTTP_PORTS` whose User-Agent contains "gobuster". It detects the default name of one tool, not the behaviour. It alerts on every request. |
| MITRE ATT&CK | T1595.003 Active Scanning: Wordlist Scanning. Correct. The lookup table in my n8n workflow says T1083 for the same rule. T1083 is File and Directory Discovery on a host, which is wrong here. |
| Likely false positives | Almost none. An authorised test that uses the same tool. |
| Detection gaps | Any other tool. The same tool with a changed User-Agent. HTTPS. A web server on a port outside `$HTTP_PORTS`. |
| Severity I should assign | Low (Wazuh 6) for the tool name. Medium (7 to 8) for a rule that detects the behaviour. Today it is 8. |
| How I would test it | Positive: a default `gobuster dir` run against the web app. Variant: the same run with a browser-like User-Agent, then a different tool. Both are missed today. A rule on bursts of 404 answers should catch both. Negative: normal browsing of the app, including a few broken links. |

### SID 9000005 · SQL injection

```text
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"PFE WEB SQL injection UNION SELECT attempt in URI"; http.uri; content:"UNION"; nocase; pcre:"/UNION\s+(ALL\s+)?SELECT/i"; classtype:web-application-attack; sid:9000005; rev:1; metadata:pfe-mitre T1190;)
```

| Question | Finding |
|---|---|
| What it detects | The words UNION and SELECT, separated by whitespace, in the URL of an HTTP request. |
| MITRE ATT&CK | T1190 Exploit Public-Facing Application. Correct. |
| Likely false positives | Tools that put SQL in URLs for good reasons, such as database admin panels and reporting tools. A search for a phrase like "student union select committee". Approved web scanners. |
| Detection gaps | Only one family of SQL injection. Only the URL, not the request body, cookies or headers. Only whitespace between the two words. HTTPS. It flags an attempt and cannot say whether data came back. |
| Severity I should assign | Medium to High (Wazuh 9) for an attempt. High (12) when there was scanning before it or there is proof of success after it. Today it is 10. |
| How I would test it | Positive: in my test I forced the scanner to use only UNION queries. Repeat it without forcing a technique and note which requests are missed. Variant: the app's next difficulty level, which sends the value in a POST body. Negative: put the search phrase above in any URL parameter. It fires, which shows the false positive. |

### SID 9000006 · Reverse shell

```text
alert tcp $HOME_NET any -> $HOME_NET [4444,4445,1234,9001,31337] (msg:"PFE TROJAN Reverse shell callback on common attack port"; flow:established,to_server; classtype:trojan-activity; sid:9000006; rev:1; metadata:pfe-mitre T1059.004;)
```

| Question | Finding |
|---|---|
| What it detects | Any established TCP connection between two lab addresses to destination port 4444, 4445, 1234, 9001 or 31337. There is no check of the content. It is a port list, not a shell detector. It alerts on every client packet of the connection. |
| MITRE ATT&CK | T1571 Non-Standard Port, because that is what the rule can see. My file says T1059.004 Unix Shell. That is what I did as the attacker, but the rule has no view of a shell. |
| Likely false positives | Any normal service on those ports. Several of them are default ports of developer tools, admin consoles and test frameworks. |
| Detection gaps | A shell on any other port, including 80 or 443. An encrypted shell. A bind shell, where the attacker connects in. And the direction: both ends must be inside `$HOME_NET`. That only happens because my attacker VM sits on the lab subnet. A real callback goes to an outside address and would not match. |
| Severity I should assign | Low to Medium (Wazuh 7) as a hint based on a port. Critical (13 or more) only for a rule that sees shell content or a host event. Today it is 14: the highest level in the set, on the weakest logic. |
| How I would test it | Positive: the lab shell to port 4444. I expect one alert, not 97. Variant: the same shell to port 443, which is missed. Negative: a simple web server on port 9001 on one VM and one request to it from another. It fires, which shows the false positive. |

### SID 9000007 · DNS exfiltration

```text
alert dns $HOME_NET any -> any 53 (msg:"PFE EXFIL DNS exfiltration long encoded subdomain label"; dns.query; pcre:"/(?:[a-z0-9]{40,}\.)/i"; classtype:policy-violation; sid:9000007; rev:1; metadata:pfe-mitre T1048.003;)
```

| Question | Finding |
|---|---|
| What it detects | A DNS query to port 53 whose name contains 40 or more letters and digits in a row, followed by a dot. One query is enough. My comments call it "high-entropy", but nothing measures entropy. It measures length. |
| MITRE ATT&CK | T1071.004 Application Layer Protocol: DNS when DNS is used as a command channel, which is what a tunnelling tool does. T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol for plain data theft over DNS. My file uses T1048.003 but names it "Exfiltration Over Alternative Protocol: DNS", which is not its name. |
| Likely false positives | Services that put hashes or tokens in host names: antivirus and reputation lookups, some CDNs and tracking domains. A SHA-1 hash is exactly 40 hex characters. |
| Detection gaps | Data cut into shorter labels. Encodings that use a hyphen or an underscore. Data that comes back in DNS answers. Encrypted DNS. Slow exfiltration. Also, the rule has no fixed text to match, only a regex, so the regex runs on every DNS query. That is fine in a lab and costly on real traffic. |
| Severity I should assign | Low (Wazuh 5 to 6) for one long label. High (10 to 12) for many such queries from one host in a short time. Today it is 12 for a single query. |
| How I would test it | Positive: my test was one hand-made query with `dig`. A real tunnelling tool between the lab VMs would be a better test. Negative: one query with a label of 40 hex characters, like a hash lookup. It fires, which shows the false positive. Variant: the same data cut into 30-character labels, which is missed. |

## Wazuh rules

All 7 Wazuh rules have the same shape. This is the first one:

```xml
<rule id="100001" level="7">
  <if_group>suricata</if_group>
  <field name="alert.signature_id">^9000001$</field>
  <description>PFE RECON: Nmap SYN port scan detected (Suricata SID 9000001)</description>
  <mitre>
    <id>T1046</id>
  </mitre>
  <group>recon,nmap,pfe_custom,</group>
</rule>
```

Each rule matches one Suricata SID and adds a level, a MITRE ID and groups. So the detection logic, the false positives and the gaps all belong to the Suricata rule. That is why this table is short.

| Rule | What it detects | MITRE ATT&CK | Likely false positives | Detection gaps | Severity I should assign | How I would test it |
|---|---|---|---|---|---|---|
| 100001 | Suricata SID 9000001 fired | T1046 Network Service Discovery | Same as SID 9000001 | Same, plus one Wazuh alert per Suricata alert with no grouping | Low, level 6 (now 7) | Paste one saved `eve.json` alert into `wazuh-logtest`. Check the rule ID, level and groups |
| 100002 | Suricata SID 9000002 fired | T1046 Network Service Discovery (file: T1595) | Same as SID 9000002 | Same | Low, level 6 (now 7) | Same method |
| 100003 | Suricata SID 9000003 fired | T1110.001 Brute Force: Password Guessing (file: T1110) | Same as SID 9000003 | Same, and it is never joined with the victim's SSH log | Medium, level 8 (now 10) | Same method, then compare with the sshd alerts from the victim's agent in the same minute |
| 100004 | Suricata SID 9000004 fired | T1595.003 Active Scanning: Wordlist Scanning | Same as SID 9000004 | Same | Low, level 6 (now 8) | Same method |
| 100005 | Suricata SID 9000005 fired | T1190 Exploit Public-Facing Application | Same as SID 9000005 | Same | Medium to High, level 9 (now 10) | Same method |
| 100006 | Suricata SID 9000006 fired | T1571 Non-Standard Port (file: T1059.004) | Same as SID 9000006 | Same | Low to Medium, level 7 (now 14) | Same method |
| 100007 | Suricata SID 9000007 fired | T1071.004 Application Layer Protocol: DNS, and T1048.003 | Same as SID 9000007 | Same | Low, level 6 for one query (now 12). High, level 10, if the Suricata rule counts many queries | Same method |

Findings that apply to all seven:

1. **They only relabel.** No rule looks at two events together, counts anything, or excludes a known-good source. Joining events is the main thing a SIEM rule can do that a sensor rule cannot, and none of mine does it.
2. **The levels do not follow confidence.** The port-list rule is level 14. A single DNS query is level 12. Every rule is 7 or higher.
3. **Two group names claim things that were not seen.** Rule 100003 has the group `authentication_failed`, but it saw connections, not failed logins. Wazuh's own sshd rules use that group for real login failures. Rule 100006 has `trojan,malware`, but it saw a port number.
4. **The parent could be more exact.** `<if_group>suricata</if_group>` works. `<if_sid>86601</if_sid>` points at Wazuh's built-in "Suricata alert" rule, so only alert events can reach my rule.
5. **The descriptions are fixed text.** Adding `$(src_ip)` shows who triggered the alert without opening the JSON.

With the levels I propose, rules 100003, 100005 and 100006 pass the level 7 filter to n8n. Rule 100007 passes only if its Suricata rule is changed to count many queries. Scans and single DNS queries stay stored and searchable but open no case. If I want a case for every scenario in a demo, the better fix is one case per source, not higher levels.

### Three things outside the rule files that change what the rules mean

1. **The forwarding filter.** Level 7 or higher plus the group `pfe_custom` means that today every alert from every rule is sent to n8n, one webhook call per alert.
2. **The ATT&CK mapping lives in three places.** The Suricata `metadata`, the Wazuh `<mitre>` tag and a lookup table in the n8n workflow. They disagree for three rules (100002, 100003 and 100004).
3. **Case severity does not come from the rule.** In my workflow, the TheHive severity comes from the summary written by an off-the-shelf local language model, not from the Wazuh level. A fixed mapping from level to severity would be easier to defend. The last phase also adds an automatic block step after the case is created, and I could not find a severity condition on that step in my own docs. That makes every false positive more expensive.

## Improved rules (all UNTESTED)

None of these rules was loaded into Suricata or Wazuh. They were not even syntax-checked, because there was no Suricata or Wazuh on the machine where the review was written. The regexes were tried on a few sample strings in Python, which is not the regex engine Suricata uses. The first step for each rule is `suricata -T` (or `wazuh-logtest`), then the lab scenario again.

I kept each SID and raised `rev` to 2. My Wazuh rules match on the SID, so nothing downstream breaks when a message changes. The thresholds are the old numbers or guesses. I have no baseline of normal traffic to justify better ones.

### Suricata

**SID 9000001 rev 2 (UNTESTED)**

```text
alert tcp any any -> $HOME_NET any (msg:"PFE RECON High rate of TCP SYN from one source - possible port scan"; flow:to_server; flags:S,12; threshold:type both, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:9000001; rev:2; metadata:mitre_technique_id T1046;)
```

- `detection_filter` became `threshold:type both`: one alert per source per 10-second window instead of one per packet (1,732 alerts in my log).
- `flags:S` became `flags:S,12`: the form ET Open's own SSH scan rule uses. It ignores the two ECN bits, so SYN packets from hosts that use ECN are counted too.
- `flow:to_server` added: only client-to-server SYN packets. My notes say Suricata printed a "poor rule" warning for my SYN-only SSH rule until this was added.
- New message: it no longer says "Nmap", because nothing in the rule is specific to Nmap.
- `metadata` key renamed to `mitre_technique_id`: the key name the ET Open rules use. Nothing in my project reads the old key.

**SID 9000002 rev 2 (UNTESTED)**

```text
alert http any any -> $HOME_NET any (msg:"PFE RECON Nmap Scripting Engine default User-Agent"; flow:established,to_server; http.user_agent; content:"Nmap Scripting Engine"; nocase; threshold:type limit, track by_src, count 1, seconds 60; classtype:attempted-recon; sid:9000002; rev:2; metadata:mitre_technique_id T1046;)
```

- `flow:established,to_server` added: only real client requests on a completed connection.
- `threshold:type limit` added: one alert per source per minute instead of one per request.
- ATT&CK ID changed to T1046: the two Nmap rules now agree.

**SID 9000003 rev 2 (UNTESTED)**

```text
alert tcp any any -> $HOME_NET 22 (msg:"PFE BRUTEFORCE High rate of new SSH connections from one source"; flow:to_server; flags:S,12; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-user; sid:9000003; rev:2; metadata:mitre_technique_id T1110.001;)
```

- `threshold:type both`, `flags:S,12` and `flow:to_server`: same three reasons as SID 9000001.
- New message: it names what is measured, a connection rate, because the rule cannot see logins.
- ATT&CK ID changed to the sub-technique T1110.001: guessing from a wordlist is Password Guessing.
- The result is the same logic as ET Open's "Potential SSH Scan" rule (SID 2001219), which ET rates as Informational.

**SID 9000004 rev 2 (UNTESTED)**

```text
alert http any any -> $HOME_NET any (msg:"PFE WEB Directory brute-force tool User-Agent - gobuster"; flow:established,to_server; http.user_agent; content:"gobuster"; nocase; threshold:type limit, track by_src, count 1, seconds 60; classtype:web-application-attack; sid:9000004; rev:2; metadata:mitre_technique_id T1595.003;)
```

- `$HTTP_PORTS` became `any`: Suricata recognises HTTP on any port, so a web server on another port is covered. SID 9000002 already did this.
- `flow` and `threshold:type limit` added: one alert per source per minute instead of one per request (1,619 alerts in my log).

**New SID 9000011, companion to 9000004 (UNTESTED)**

```text
alert http $HOME_NET any -> any any (msg:"PFE WEB Burst of HTTP 404 responses to one client - possible content discovery"; flow:established,to_client; http.stat_code; content:"404"; threshold:type both, track by_dst, count 30, seconds 10; classtype:web-application-attack; sid:9000011; rev:1; metadata:mitre_technique_id T1595.003;)
```

- Why it exists: it detects the behaviour, many missing pages asked for in a short time, whatever the tool or the User-Agent.
- `track by_dst`: the answers go from the server to the client, so the destination is the scanning client.
- 30 in 10 seconds is a guess and needs a baseline.

**SID 9000005 rev 2 (UNTESTED)**

```text
alert http any any -> $HOME_NET any (msg:"PFE WEB SQL injection UNION SELECT attempt in URI"; flow:established,to_server; http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; pcre:"/UNION(?:\s|\+|\(|\/\*!\d*|\/\*.*?\*\/)+(?:(?:ALL|DISTINCT)(?:\s|\+|\(|\/\*.*?\*\/)+)?SELECT/i"; threshold:type limit, track by_src, count 1, seconds 60; classtype:web-application-attack; sid:9000005; rev:2; metadata:mitre_technique_id T1190;)
```

- Second `content` with `distance:0`: a cheap check that SELECT comes after UNION before the regex runs.
- New regex: it also accepts an SQL comment, a bracket or a plus sign between the two words, and the keyword DISTINCT. The first version accepted whitespace only.
- `$HTTP_PORTS` became `any`, plus `flow` and `threshold:type limit`: same reasons as SID 9000004.
- Not fixed: it is still URL-only and still fires on the "student union select committee" search. For POST forms, ET Open already has a request-body rule (SID 2053468), so I did not write one.

**SID 9000006 rev 2 (UNTESTED), kept only as a low-severity hint**

```text
alert tcp $HOME_NET any -> any [4444,4445,1234,9001,31337] (msg:"PFE POLICY Outbound TCP session to a port often used by shell listeners"; flow:established,to_server; threshold:type limit, track by_src, count 1, seconds 300; classtype:misc-activity; sid:9000006; rev:2; metadata:mitre_technique_id T1571;)
```

- Destination `$HOME_NET` became `any`: a real callback goes outside the network. It still matches the lab.
- `threshold:type limit` added: one alert per source per 5 minutes instead of one per packet (97 alerts in my log).
- New message and `classtype:misc-activity`: it says "port", not "trojan", which is what the rule sees.
- ATT&CK ID changed to T1571 Non-Standard Port.

**New SID 9000012, companion to 9000006 (UNTESTED)**

```text
alert tcp $HOME_NET any -> any any (msg:"PFE C2 Interactive shell banner in cleartext TCP - possible reverse shell"; flow:established,to_server; content:"job control"; pcre:"/(?:no job control in this shell|job control turned off)/"; threshold:type limit, track by_src, count 1, seconds 300; classtype:trojan-activity; sid:9000012; rev:1; metadata:mitre_technique_id T1059.004;)
```

- Why it exists: it looks for the text an interactive shell prints when it starts without a terminal, on any port. This is the rule that can honestly carry T1059.004.
- Limit: it only sees shells that are not encrypted, which is what my lab used.

**SID 9000007 rev 2 (UNTESTED)**

```text
alert dns $HOME_NET any -> any 53 (msg:"PFE EXFIL Repeated DNS queries with a long encoded label - possible DNS tunnel"; dns.query; pcre:"/(?:^|\.)[a-z0-9_-]{40,63}\./i"; threshold:type both, track by_src, count 10, seconds 60; classtype:policy-violation; sid:9000007; rev:2; metadata:mitre_technique_id T1071.004;)
```

- `threshold:type both` with 10 in 60 seconds: it alerts on a pattern of queries, not on one. A single long label is common in normal traffic.
- New regex: it matches a whole label and allows hyphen and underscore, so more encodings are covered and part of a label can no longer match.
- New message: it no longer says "high-entropy".
- Side effect: my one-query `dig` test will not fire any more. The test needs a loop of at least 10 queries.
- Not fixed: it is still a regex with no fixed text, so it still runs on every query.

The two new SIDs each need a Wazuh rule (for example 100011 and 100012) before they reach n8n.

### Wazuh

**Base rule pattern, shown for 100006 (UNTESTED)**

```xml
<rule id="100006" level="7">
  <if_sid>86601</if_sid>
  <field name="alert.signature_id">^9000006$</field>
  <description>PFE POLICY: outbound session from $(src_ip) to a common shell-listener port (Suricata SID 9000006)</description>
  <mitre>
    <id>T1571</id>
  </mitre>
  <group>pfe_custom,pfe_c2,</group>
</rule>
```

- `<if_group>suricata</if_group>` became `<if_sid>86601</if_sid>`: only Suricata alert events can reach the rule.
- Level 14 became 7: the level follows what the rule can prove.
- Groups `trojan,malware` removed: no malware was seen.
- `$(src_ip)` added to the description: the alert line shows who triggered it.
- The same four changes apply to the other six rules, with the levels and ATT&CK IDs from the table above. On 100003, the group `authentication_failed` goes away.

**New correlation rule 100021 (UNTESTED)**

It needs the group `pfe_recon` added to rules 100001, 100002 and 100004 first.

```xml
<rule id="100021" level="12" timeframe="600">
  <if_sid>100005</if_sid>
  <if_matched_group>pfe_recon</if_matched_group>
  <same_field>src_ip</same_field>
  <description>PFE CORRELATION: SQL injection attempt from $(src_ip) after scanning from the same address in the last 10 minutes</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>pfe_custom,pfe_correlation,</group>
</rule>
```

- Why it exists: it is the first rule in the set that uses more than one event. The high level comes from the sequence, a scan followed by an exploit attempt, not from one packet.
- The part I am least sure about is `<same_field>` on the JSON field `src_ip`. To test it, paste a scan alert and then a SQL injection alert into one `wazuh-logtest` session.

## The three most important weaknesses

### 1. Alerts per packet, with no grouping anywhere

All seven rules alert on every matching packet, request or query. Two of them use `detection_filter`, but that only decides when alerting starts. After that it lets every match through. The result in my own log: 1,732 alerts for the scan rule, 1,619 for the directory rule and 97 for one shell. Wazuh passes each one on, and n8n gets one webhook call per alert. My notes for the later phases say I replayed alerts by posting them straight to the webhook, to avoid filling the Wazuh alert queue with scan alerts. The detection layer was too noisy for my own pipeline.

How a SOC covers it:

- **A threshold at the sensor**: `threshold:type both` or `type limit`, so one source gives one alert per time window.
- **A correlation rule in the SIEM**: group repeated alerts from one source into one higher-level alert.
- **A deduplication key in the SOAR**: same rule and same source inside a time window update one case instead of opening a new one.

### 2. Rules built around one tool and one lab layout

Two rules match a tool's default User-Agent. One matches a list of ports. One matches a single pair of SQL keywords. One matches a label length. The reverse shell rule only works because my attacker VM sits inside the monitored network. I tested each rule with the tool's default command. For SQL injection I even forced the technique my rule looks for. So the tests proved that the rules match my own commands, not that they match the attack.

How a SOC covers it:

- **Another data source that shows behaviour.** Flow records show how many different ports one source touched, which is a real scan signal. Web server access logs show the rate of 404 answers and still work for HTTPS, because the server logs after decryption. DNS logs show the number of queries and of different sub-domains per parent domain.
- **A maintained ruleset for breadth.** ET Open is already loaded in my lab, and three of my seven rules repeat signatures it already has. ET's versions only match a source outside `$HOME_NET`. My attacker VM was inside it, so they would not have fired in my lab.
- **Testing with variants.** Each rule is re-tested with a changed version of the attack, and the misses are written down.

### 3. Network only, one event at a time, and severity that ignores confidence

Every rule sees an attempt on the wire. None can say whether it worked: whether the SSH login succeeded, whether the SQL injection returned data, whether a shell really started. Encrypted traffic is invisible. Wazuh agents were running on the lab VMs, but my custom rules do not use a single host log. And the levels are upside down: the weakest rule has the highest level.

How a SOC covers it:

- **Host data.** SSH authentication logs for failures followed by a success, web server logs, and process events on the web server, such as the web server account starting a shell.
- **Correlation.** A network attempt plus a host confirmation raises the level. A network attempt alone stays low.
- **A threshold for escalation.** Only correlated or confirmed events reach High. A single weak signal is stored and searchable, and does not open a case or trigger a block.

## What I learned

1. A rule that fires is not a rule that works. My validation script checked that each rule fired at least once. It never checked how many times it fired, what else made it fire, or what it missed.
2. In Suricata, `detection_filter` decides when alerting starts. It does not limit how many alerts follow. `threshold` does that. One rule gave me 1,732 alerts in one test session.
3. I should map ATT&CK to what the rule can see, not to what I did as the attacker. My "reverse shell" rule sees a port number, so it is T1571, not T1059.004.
4. Severity should follow confidence. My highest level, 14, was on my weakest rule, a list of ports.
5. I wrote the rules for my lab's layout. The attacker VM was inside the monitored network, so a rule that needs both ends to be internal passed its test and would miss a real callback.
6. My Wazuh rules only renamed Suricata alerts. The value of a SIEM rule is in joining events: a scan and then an exploit, or a network attempt and a host log.

## Checked against official sources

Done on 16 Nov 2026. This checks facts, not behaviour: no rule on this page was loaded or run.

| Claim on this page | Source | Result |
|---|---|---|
| The 12 ATT&CK technique IDs and their names | attack.mitre.org, ATT&CK v20.1 | All 12 match. None is deprecated or revoked. |
| T1571 fits a rule on ports 4444, 4445 and 31337 | T1571 page | Its examples include a group that used ports 4444, 4445 and 31337 for C2. |
| T1595.003 fits a gobuster rule | T1595.003 page | The description names GoBuster as an example tool. |
| T1046 covers both Nmap rules | T1046 page | The description lists port, vulnerability and wordlist scans. |
| Wazuh rule 86601 is the built-in "Suricata alert" rule | Wazuh ruleset at tag v4.11.2, file `0475-suricata_rules.xml` | Confirmed. It is the child of rule 86600 that matches `event_type` equal to `alert`. |
| The built-in sshd rules are the 5700 series and use the group `authentication_failed` | Same ruleset, file `0095-sshd_rules.xml` | Confirmed. IDs run from 5700 to 5763, and the login-failure rules carry that group. |
| The shape of my correlation rule exists in Wazuh | Same ruleset, rule 40112 | Confirmed for `timeframe` with `if_matched_group`. Rule 40112 uses `same_source_ip` where mine uses `same_field`, so mine is still untested. |
| `detection_filter` alerts on every match after the threshold | Suricata 6.0.4 documentation, thresholding page | Confirmed. It "generates an alert for each rule match after the initial threshold has been reached". |
| `flags:S,12` is valid and ignores the ECN bits | ET Open rules for Suricata 6.0, and the Suricata documentation for `tcp.flags` | Confirmed. ET Open's SSH scan rule uses this exact form. |
| ET Open already has some of my signatures | ET Open rules for Suricata 6.0 | Confirmed for three: the Nmap User-Agent (SID 2009358), the SSH connection rate (SID 2001219) and UNION SELECT in the URL (SID 2006446). I found no gobuster rule in the four files I searched. |

One more thing this check showed: ET rates its own SSH scan rule and Nmap User-Agent rule as Informational. That supports lowering my levels for the same detections.

## Honest limits

- **Lab only.** Three VMs and no normal user traffic. The false-positive notes are reasoning, not measurements. I have no false-positive rate and no detection rate.
- **The only test was "did the rule fire at least once?"**, on the default form of one attack. My log does not tie each alert to the attack that caused it. The SQL injection rule fired twice, with the scanner forced to one technique. The DNS rule was tested with a hand-made query, not with a real tunnelling tool.
- **Every improved rule is untested.** Not loaded, not syntax-checked, not run against the scenarios. The regexes were only tried on sample strings in Python.
- **The thresholds are guesses.** 20 in 10 seconds, 5 in 60 seconds, 30 in 10 seconds and 10 in 60 seconds have no baseline behind them.
- **Old sensor version.** My lab ran Suricata 6.0.4, an old release line. The improved rules are written for it.
- **The reviewed file may differ from the tested one.** My session notes say I added `flow:to_server` to SID 9000003 directly on the sensor. The repo file does not have it. The review used the repo files.
- **The later pipeline stages were tested with synthetic alerts.** The evidence I kept for the enrichment, case creation and response stages shows alerts posted to the webhook, not live attacks. So the full path from a live attack to a TheHive case was not shown for all 7 rules.
- **The review was done with an AI assistant.** It read files and logs and did not touch the lab. The facts it relied on were checked against official sources (see the section above). Which ATT&CK technique fits a rule best is still a judgement.
- **No machine learning.** The pipeline calls an off-the-shelf local language model to write a one-line summary and suggest a severity. It does no detection, and I trained nothing.

## Privacy check (before every commit and post)

- [x] No real IP addresses, hostnames or usernames
- [x] No passwords, keys or tokens
- [x] No school or employer data
- [x] Screenshots cropped to what matters (none on this page)
- [x] gitleaks passed on commit
