# LinkedIn draft · detection rules review

Status: draft, not posted.

---

Before publishing the detection rules from my final-year SOC lab, I asked an AI assistant to review them the way a senior detection engineer would review a junior's work.

The lab: an isolated VMware network, one attacker VM, one victim, Suricata and Wazuh on a sensor. 7 attack scenarios, 14 custom rules.

One lesson stood out: a rule that fires is not a rule that works.

My port-scan rule passed its test. It also produced 1,732 alerts in a single test session. I had used Suricata's detection_filter, which decides when alerting starts and then alerts on every matching packet. That noise is why I tested the later stages of my pipeline with synthetic alerts instead of live scans.

The proposed fix is one line: a threshold that gives one alert per source per time window. I have not tested it yet, and the write-up says so.

The review also covers false positives, gaps, ATT&CK mapping and three weaknesses of the whole rule set. These are lab results, not production numbers.

Write-up: https://github.com/souchaine/soc-lab-notebook/blob/main/writeups/pfe-detection-rules-review.md

#DetectionEngineering #Suricata #Wazuh #SOC
