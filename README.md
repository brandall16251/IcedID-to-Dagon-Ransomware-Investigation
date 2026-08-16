# IcedID-to-Dagon Ransomware Investigation

This project began as the [**Scanned Document 468**](https://github.com/jirosgyros/soc-ctf-scanned-document-468) Splunk CTF shared in the InfoSec Wizard Academy Discord led by Mike Small and Anthony Jirouscheck. 

My initial intent was to complete the CTF and create a writeup of my methods. Upon receiving the log set, I decided against this method as its scope deterred my learning. As such, this project features an investigation led by 3 facets: (1) I was told this was a phishing-based incident by the CTF creator (2) evidence-based investigative methods and (3) the CTF questions for support when needed. 

While the result does use the CTF questions for guidance at times, the primary investigation, methods, and lessons learned arose from my experience as an investigator. 

The result is a project entailing a higher level [Incident Report](Incident-Report.md), detailed [Investigation Steps, Methods, and Lessons Learned](Investigation-Steps-Methods-and-Lessons-Learned.md), and an [Appendix](Appendix-Investigative-Pivots.md) containing pivots, dead-ends, and corrections.

## Start Here

| If you want to...                        | Read...                                                                                                 |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Review the incident quickly              | [Incident Report](Incident-Report.md)                                                                   |
| Evaluate my investigative reasoning      | [Investigation Steps, Methods, and Lessons Learned](Investigation-Steps-Methods-and-Lessons-Learned.md) |
| Study the false leads and omitted pivots | [Appendix: Investigative Pivots](Appendix-Investigative-Pivots.md)                                      |
| Inspect the supporting evidence          | [Screenshot assets](assets/screenshots/)                                                                |

Hiring managers are recommended to start with the [Incident Report](Incident-Report.md), then sample the process document if desired.

Learners may get more value by reading the[Investigation Steps, Methods, and Lessons Learned](Investigation-Steps-Methods-and-Lessons-Learned.md) and/or [appendix](Appendix-Investigative-Pivots.md).

## Project Purpose

Use the given CTF to practice investigation, documentation, and the presentation thereof while improving my workflow, methods, and background knowledge as an investigator. 

## Tools and Telemetry

Splunk SIEM with the following source types: 

- Proofpoint TAP (email)
- Web proxy 
- Zeek flow and DNS
- Palo Alto Networks perimeter-firewall 
- Windows Security events
- Sysmon 
- OSINT from the [DFIR Report](https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/), [Mphasis](https://www.mphasis.com/content/dam/mphasis-com/global/en/home/services/cybersecurity/icedid-infection-to-dagon-locker-ransomware-apr29-22-7.pdf), and VirusTotal.

## Scope and Limitations

- The scope was investigation and documentation, not live containment, eradication, recovery, or malware reverse engineering.
- Note that screenshots may display differing timestamps due to synthetic lab dataset, the timeline used is consistent with the time-of-incident as the organization would have seen it. 

## Analysis Language

Each investigative step separates direct observation from interpretation:

- **Observed Activity** states what the available record contains objectively.
- **Assessment** Low, Medium, or High confidence stated.
- **Hypothesis — Posited** introduces an explanation that still requires support.
- **Hypothesis — Supported** restates a prior hypothesis when new evidence strengthens it.
- **Validation** identifies what would strengthen the assessment or states when no additional validation was required for the investigative decision.

## OSINT and AI Use

OSINT helped me understand unfamiliar artifacts and form hypotheses--it did not independently validate findings. 

AI was used for ID comparison, timeline normalization, and formatting for my custom documentation templates. It did not perform the original investigation or make decisions therein, where only occasionally did I ask AI to help explain an artifact (typically for codes like "`0xC4C8`").
