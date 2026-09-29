# Red Team Learning Order: Windows Priv Esc vs Active Directory - Course Provider Recommendations

## TCM Security: Explicit Course Sequencing

### Takeaway
TCM Security's PNPT bundle puts Active Directory attacks inside the foundational Practical Ethical Hacking (PEH) course, with Windows Privilege Escalation as a separate standalone course taken AFTER PEH. Their recommended PNPT bundle order is: PEH first (which covers AD), then OSINT, External Pentest Playbook, Linux Priv Esc, Windows Priv Esc last.

### Cited Findings
- The PNPT Training consists of five full-length video courses in this recommended order: Practical Ethical Hacking (25 hours), OSINT Fundamentals (9 hours), External Pentest Playbook (3.5 hours), Linux Privilege Escalation for Beginners (6.5 hours), and Windows Privilege Escalation for Beginners (7 hours). TCM Security "strongly recommends that the courses be taken in the order listed." — [TCM Security PNPT Training Overview PDF](https://certifications.tcm-sec.com/wp-content/uploads/2022/01/TCMS-PNPT-Training-Overview.pdf); [How to Pass the PNPT Exam - TCM Security](https://tcm-sec.com/how-to-pass-the-pnpt-exam-first-time/)
- The Practical Ethical Hacking (PEH) course covers Active Directory extensively as its own dedicated section: "Attacking Active Directory: Initial Attack Vectors," "Attacking Active Directory: Post-Compromise Enumeration," "Attacking Active Directory: Post-Compromise Attacks." These AD sections appear in the second half of PEH, after a mid-course capstone. — [GitHub: TCM-Course-Resources/Practical-Ethical-Hacking-Resources](https://github.com/TCM-Course-Resources/Practical-Ethical-Hacking-Resources/blob/master/README.md)
- The TCM Exploitation Analysis Learning Path explicitly lists courses in this order: Practical Ethical Hacking course, Windows Privilege Escalation course, Linux Privilege Escalation course. PEH (which contains the AD content) is listed first. — [Exploitation Analysis Learning Path - TCM Security](https://certifications.tcm-sec.com/exploitation-analysis-learning-path/)
- As of May 7, 2025, Windows and Linux Privilege Escalation courses are no longer part of the TCM All-Access Membership but remain bundled with PNPT voucher purchases. — [Privilege Escalation Course Retirement - TCM Security](https://tcm-sec.com/course-retirement-privilege-escalation/)
- Within the PEH course itself, no dedicated standalone Windows local privilege escalation section exists in the table of contents. Privilege escalation techniques appear within the AD post-compromise sections. — [GitHub: TCM-Course-Resources/Practical-Ethical-Hacking-Resources README](https://github.com/TCM-Course-Resources/Practical-Ethical-Hacking-Resources/blob/master/README.md)

### Inferences
- TCM's model is effectively AD-first (inside PEH), Windows Priv Esc as a supplement taken after. This is the OPPOSITE of the OSCP sequencing. TCM's PEH teaches students to attack AD without first teaching deep local Windows priv esc. The standalone priv esc course is treated as an add-on for exam polish, not a prerequisite.
- The PNPT certification exam focuses on internal network compromise and AD traversal - which explains why PEH (AD attacks) is foundational and standalone priv esc is supplementary.

### Gaps
- The actual page text of the Exploitation Analysis Learning Path (certifications.tcm-sec.com) was blocked by network proxy, so the exact wording of course descriptions and any explicit prerequisite statements could not be verified from the source page.
- It is unclear whether the PEH course contains any local Windows priv esc content (unrelated to AD) or whether it assumes that knowledge from external sources.

---

## OSCP / Offensive Security PEN-200: Explicit Module Order

### Takeaway
OSCP PEN-200 is the clearest example of priv esc-before-AD sequencing. Windows Privilege Escalation is Module 07; Active Directory modules begin at Module 10. This ordering is explicit in the course structure.

### Cited Findings
- A community cheatsheet built from the 2024-2025 PEN-200 course shows the following module order: 07 Windows Privilege Escalation, 08 Linux Privilege Escalation, 09 Tunneling, 10 Active Directory-Enumeration, 11 Active Directory-Authentication, 12 Active Directory-Lateral Movement. Windows priv esc (Module 07) appears before all AD modules (Modules 10-12). — [GitHub: fatalxs/oscp-cheatsheet (2024-2025)](https://github.com/fatalxs/oscp-cheatsheet)
- The official OffSec PEN-200 course description states it covers "performing Windows and Linux privilege escalation and lateral movements, including pivoting and tunneling techniques, using Active Directory, attacking Active Directory authentication, and lateral movement in Active Directory." The order in the description matches the module order - priv esc is listed before AD. — [OffSec PEN-200 course page](https://www.offsec.com/courses/pen-200/)
- In November 2024, OffSec rebranded OSCP as OSCP+ and made Active Directory exploitation mandatory (no longer optional). Active Directory accounts for 26% of the exam, while Escalating Privileges accounts for 18%. — [OSCP+ Roadmap 2026 - HackerDNA](https://hackerdna.com/blog/oscp-preparation-guide)
- Web exploitation and Active Directory should account for roughly 70% of OSCP preparation time, with Linux and Windows local privilege escalation as the next priority. This community advice reflects the exam weighting (AD is worth more) but the course itself still teaches priv esc first. — [OSCP+ Roadmap 2026 - HackerDNA](https://hackerdna.com/blog/oscp-preparation-guide)

### Inferences
- OffSec's curriculum philosophy is that local privilege escalation is a foundational skill that students need before tackling Active Directory. The reasoning is likely that you often land on a low-privilege local shell before you touch AD, so local priv esc skills are needed to set up the starting point for AD attacks.
- The 2024 OSCP+ update making AD mandatory did NOT change the course structure - priv esc still comes before AD modules.

### Gaps
- The OffSec course website (offsec.com) was blocked by the network proxy. The module numbering comes from a community cheatsheet, not from the official OffSec syllabus page. The community ordering is consistent with the official course description text, however.

---

## SANS SEC565 (Red Team Operations and Adversary Emulation): Prerequisites

### Takeaway
SANS SEC565 does not list Windows privilege escalation as an explicit prerequisite by name. It states that "general penetration testing concepts and tools" are recommended. SEC560 (Enterprise Penetration Testing, which does cover priv esc and AD) is the natural feeder course into SEC565.

### Cited Findings
- SEC565 prerequisite statement: "The concepts and exercises in this course are built on the fundamentals of offensive security. An understanding of general penetration testing concepts and tools is encouraged, and a background in security fundamentals will provide a solid foundation upon which to build Red Team concepts." No specific mention of privilege escalation or Active Directory as prerequisites by name. — [SANS SEC565 course page via NICCS](https://niccs.cisa.gov/training/catalog/sans-institute/sec565-red-team-operations-and-adversary-emulation-grtp)
- SEC565 is a 6-day course that leads to the GIAC Red Team Professional (GRTP) certification. The course covers DNS Extraction, Domain Privilege Escalation, Access Token Manipulation, Pass-The-Hash, Pass-The-Ticket, Kerberoasting, Silver Ticket, Golden Ticket, Skeleton Key, and AD Certificate Services - all of which assume prior foundational pentesting skills. — [SANS SEC565 course page](https://www.sans.org/cyber-security-courses/red-team-operations-adversary-emulation)
- SANS recommends taking SEC560 or SEC504 before SEC660 (the advanced course after SEC565); those with OSCP can opt to skip prerequisites. This implies SEC560, which covers enterprise pentesting and privilege escalation, is the expected background for the offensive operations track. — [SANS SEC660 course page](https://www.sans.org/cyber-security-courses/advanced-penetration-testing-exploits-ethical-hacking)
- The SANS offensive operations roadmap lists SEC560 as a step leading to SEC565. SEC560 covers "privilege escalation, lateral movement" alongside AD attacks. — [SANS Offensive Operations Roadmap](https://www.sans.org/job-roles-roadmap/offensive-operations/)
- SEC565 explicitly teaches adversary emulation against AD environments, covering Active Directory privilege escalation techniques as course content (not prerequisite). — [SANS SEC565 Brochure PDF](https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/blt6f154ca8735f730a/65f4245dd4e0c0c5f02920f0/SANS_Institute_SEC565_Brochure.pdf)

### Inferences
- SANS's approach treats SEC560 (which covers both priv esc and AD) as the building block for SEC565. Within the SANS track, priv esc and AD pentesting are taught together in SEC560 rather than sequenced strictly - both are covered in the same enterprise pentesting course before students move to adversary emulation in SEC565.
- Because SEC565 is an adversary emulation course (not an introduction to priv esc or AD), it assumes students already know both and are ready to use them in coordinated red team engagements.

### Gaps
- The SANS website (sans.org) and their CDN (contentstack.io) were both blocked by the network proxy. The prerequisites wording above comes from a cached copy via NICCS and from search result snippets, not from the live SANS page. The exact current prerequisite text may differ.
- SANS SEC660 prerequisites specifically were found, but the exact prerequisite language for SEC565 specifically and how it differs from SEC660 could not be confirmed from primary sources.

---

## HackTheBox Academy: CPTS Penetration Tester Path Module Order

### Takeaway
HTB Academy's CPTS Penetration Tester path (28 modules) places Active Directory Enumeration & Attacks at Module 13 and Windows Privilege Escalation at Module 26 - meaning AD comes significantly BEFORE Windows local privilege escalation in this path. This is opposite to OSCP's ordering.

### Cited Findings
- The complete 28-module HTB CPTS Penetration Tester path lists modules in this confirmed order: 1-Pentest Process, 2-Getting Started, 3-Nmap, 4-Footprinting, 5-Web Info Gathering, 6-Vulnerability Assessment, 7-File Transfers, 8-Shells & Payloads, 9-Metasploit, 10-Password Attacks, 11-Attacking Common Services, 12-Pivoting/Tunneling, **13-Active Directory Enumeration & Attacks**, 14-Web Proxies, 15-Web FFuf, 16-Login Brute Forcing, 17-SQL Injection, 18-SQLMap, 19-XSS, 20-File Inclusion, 21-File Upload Attacks, 22-Command Injections, 23-Web Attacks, 24-Attacking Common Applications, **25-Linux Privilege Escalation**, **26-Windows Privilege Escalation**, 27-Reporting, 28-Attacking Enterprise Networks. — [GitHub: zeshanalioffical00-lab/HTB-CPTS-Portfolio](https://github.com/zeshanalioffical00-lab/HTB-CPTS-Portfolio)
- A second independent CPTS notes repository confirms the same module list in the same order, with AD Enumeration & Attacks appearing before both Linux and Windows Privilege Escalation modules. — [GitHub: ShortGiant13/HTB-CPTS-Notes](https://github.com/ShortGiant13/HTB-CPTS-Notes)
- HTB Academy also offers a separate "Active Directory Penetration Tester" job role path consisting of 15 modules focused specifically on AD environments. This path is described as designed for "security professionals who aim to develop skills in pentesting large Active Directory (AD) networks." — [HTB Academy: Active Directory Penetration Tester path](https://academy.hackthebox.com/path/preview/active-directory-penetration-tester)
- HTB Academy's Windows Privilege Escalation course is classified as "Medium" level and assumes "working knowledge of Windows command line and operating system fundamentals" - not prior AD pentesting knowledge. — [HTB Academy: Windows Privilege Escalation Course](https://academy.hackthebox.com/course/preview/windows-privilege-escalation)

### Inferences
- HTB's CPTS path distinguishes between AD-level attacks (network-level domain attacks like Kerberoasting, LLMNR poisoning - taught at Module 13) and Windows LOCAL privilege escalation (SeImpersonate, DLL hijacking, service misconfigurations - taught at Module 26). By teaching AD first, HTB may be prioritizing the attacks most relevant to lateral movement in enterprise networks over the local exploitation techniques used to escalate on individual hosts.
- This ordering may reflect HTB's philosophy that in real engagements, AD enumeration skills unlock more attack paths earlier than deep local priv esc knowledge does.
- Students following the HTB CPTS path will encounter AD before ever studying Windows local priv esc - which contrasts sharply with the OSCP approach.

### Gaps
- The HTB Academy website was blocked by the network proxy. Module ordering is confirmed via two independent GitHub repositories documenting student notes. This is considered reliable community documentation but is not the official HTB Academy syllabus page.
- It is unclear whether HTB Academy provides any official stated rationale for why AD comes before Windows Priv Esc in the CPTS path.

---

## TryHackMe: Red Team Path Structure

### Takeaway
TryHackMe's Red Teaming path places privilege escalation in the "Post Compromise" section (after initial access) and Active Directory as a separate later section. The sequence appears to be: Fundamentals → Initial Access → Post Compromise (contains priv esc) → Host Evasion → Active Directory. This puts priv esc before AD.

### Cited Findings
- TryHackMe's Red Teaming path covers these major sections in the following order: Red Team Fundamentals (engagement planning, OPSEC, C2 infrastructure), Initial Access (phishing, password attacks, initial compromise), Post Compromise (privilege escalation, persistence, lateral movement, data exfiltration), Host Evasion (AV bypass, intrusion detection evasion), and Active Directory. — [TryHackMe Red Teaming Training path](https://tryhackme.com/path/outline/redteaming); description via [TryHackMe Red Team path guide - SecByte](https://learn.secbyte.org/blog/tryhackme-red-team-path-guide)
- TryHackMe offers a standalone Privilege Escalation module and a standalone "Hacking Active Directory" module. The AD module states it "will teach you the basics of AD and take you on the typical journey of compromising AD during a red team." — [TryHackMe Privilege Escalation module](https://tryhackme.com/module/privilege-escalation); [TryHackMe Compromising Active Directory](https://tryhackme.com/module/hacking-active-directory)
- In the Jr Penetration Tester path, Windows Privesc appears as the thirteenth write-up in the series. Active Directory basics appear after the privilege escalation content in that path. — [TryHackMe Jr Penetration Tester - Kamal S, Medium](https://medium.com/@Kamal_S/tryhackme-jr-penetration-tester-learning-path-df079b558aa1)

### Inferences
- TryHackMe's Red Team path structure groups privilege escalation under "Post Compromise" (what you do after getting initial access on a host) and treats Active Directory as its own distinct phase after host-level techniques are mastered. This supports the priv-esc-before-AD ordering.
- The "Post Compromise" grouping reflects a logical attack chain: land on a host with low privileges → escalate locally → then pivot into AD.

### Gaps
- The TryHackMe website was blocked by the network proxy. The section ordering above is reconstructed from search result snippets and a secondary guide. The exact room-by-room sequence within the Red Teaming path could not be verified from the primary TryHackMe platform page.
- TryHackMe's path content can change over time. The current module order (as of 2024-2025) versus the documented order may have changed.

---

## Zero-Point Security CRTO: Prerequisites and Assumed Knowledge

### Takeaway
CRTO explicitly assumes prior Windows and Active Directory knowledge at the OSCP level or above. It is not designed for beginners. Within the CRTO course itself, local privilege escalation content appears before deep Active Directory exploitation content, but both require prior foundational knowledge of Windows and AD to follow.

### Cited Findings
- CRTO is "NOT a beginner-level certification and you need solid Windows/AD knowledge before attempting." Multiple 2024-2025 reviewers state that candidates need a solid foundation in Windows, Active Directory, and basic pentesting before tackling red team operations at the CRTO level. — [CyberCertReviews: CRTO 2026 Review](https://www.cybercertreviews.com/crto); [Zero-Point Security CRTO - security.university](https://security.university/resources/courses/zero-point-security-crto/)
- CRTO assumes "baseline Active Directory knowledge, covering enumeration and exploitation deeper than OSCP-tier coverage." Students are expected to arrive with AD knowledge already - the course goes deeper, not from scratch. — [Cobalt: What is CRTO?](https://www.cobalt.io/learning-center/what-is-crto)
- The CRTO course module structure covers: initial access patterns (phishing, USB, supply-chain) → local privilege escalation and persistence (local enumeration, priv esc techniques, UAC bypass, scheduled tasks) → credential theft → AD enumeration and exploitation → lateral movement → post-exploitation. Local priv esc is taught BEFORE the deep AD exploitation content within the course itself. — [Red Team Ops I CRTO Review - Jake Mayhew, LinkedIn](https://www.linkedin.com/pulse/red-team-ops-i-crto-review-adversary-simulation-jake-mayhew); [CRTO Review - I Break Stuff](https://rouvin.gitbook.io/ibreakstuff/blogs/reviews/crto-review)
- CRTO uses Cobalt Strike as its primary C2 framework and covers "Active Directory enumeration and exploitation, lateral movement under detection-aware constraints" - all of which require students to already understand basic AD concepts. — [What is CRTO - Cobalt](https://www.cobalt.io/learning-center/what-is-crto)

### Inferences
- CRTO's prerequisite model implies that the correct preparation order before CRTO is: basic pentesting skills (including Windows priv esc and basic AD) → OSCP or equivalent → then CRTO. Both priv esc and AD knowledge are PREREQUISITES, not topics introduced in sequence.
- Within CRTO itself, local priv esc content is covered before advanced AD exploitation, which is consistent with the logical attack flow of a red team engagement: gain access → escalate locally → move laterally through AD.

### Gaps
- The Zero-Point Security website (zeropointsecurity.co.uk) was blocked by the network proxy. The stated prerequisites are from third-party reviews and descriptions, not from the official course page.
- The exact wording of CRTO's "Prerequisites" or "Who Should Attend" section from the official Zero-Point Security website could not be verified.

---

## Summary Table

| Provider | Priv Esc Before AD? | Explicit Sequencing? | Notes |
|---|---|---|---|
| TCM Security (PNPT bundle) | AD First (in PEH), then Windows Priv Esc as supplement | Yes - PNPT bundle lists PEH first, Windows Priv Esc last | AD is inside PEH; Windows Priv Esc is a separate standalone course taken after |
| OSCP PEN-200 (OffSec) | YES - Windows Priv Esc (Module 07) before AD (Modules 10-12) | Yes - explicit module numbering | Clearest example of priv esc before AD |
| SANS SEC565 | Both covered in SEC560 (feeder course) before SEC565 | No explicit sequencing within SEC565 | SEC565 assumes both skills; SEC560 covers them together |
| HackTheBox Academy CPTS (28-module path) | NO - AD (Module 13) before Windows Priv Esc (Module 26) | Yes - explicit module numbering | AD-level attacks taught early; local priv esc taught after web modules |
| TryHackMe Red Team path | YES - Post Compromise (priv esc) before Active Directory section | Partial - section names, not module numbers | Priv esc is under "Post Compromise," AD is a later section |
| Zero-Point Security CRTO | Both required as PREREQUISITES; within course, local priv esc before deep AD | Yes - course assumes both; module order confirmed by reviewers | CRTO is advanced; both skills must be known before starting |
