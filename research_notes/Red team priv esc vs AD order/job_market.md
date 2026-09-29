# Red Team Job Market: Windows Priv Esc vs Active Directory Skill Sequencing

## Do red team job postings list Windows priv esc as a prerequisite separate from AD skills?

### Takeaway
Job postings do not typically list local Windows privilege escalation as a formal prerequisite separate from Active Directory skills. Both appear together as peer requirements in the same bullet point or skill category, but community roadmaps, certifications, and training curricula consistently place local priv esc before AD-domain exploitation in the learning sequence.

### Cited Findings
- A senior red team operator posting (builtin.com, 2024-2025) requires: minimum 3 years with pen testing frameworks, minimum 2 years independently conducting red team exercises, minimum 2 years developing payloads that bypass A/V and EDR, and "experience performing engagements on cloud, hybrid, multi- and/or single-tenant active directory environments." Windows local priv esc is embedded under the umbrella "every phase of a red team exercise" rather than listed as a discrete prerequisite. — [Red Team Operator - Senior, BuiltIn](https://builtin.com/job/red-team-operator-senior/3531648)
- A Packetlabs infrastructure/red team posting explicitly lists: "internal and external network penetration testing, privilege escalation, Active Directory security assessments, and lateral movement testing" together as a single requirement line, treating them as peer skills rather than a sequence. — [Penetration Tester – Infrastructure, Red Team at Packetlabs via RemoteRocketship](https://www.remoterocketship.com/us/company/packetlabs-net-2/jobs/penetration-tester-infrastructure-red-team-united-states-remote/)
- Entry-level and junior red team postings (EncryptEdge Labs internship, 2024-2025) list "knowledge of basic command-line tools and scripting" and "interest in privilege escalation and exploitation techniques" as requirements, while "familiarity with Active Directory is a plus but not mandatory." This is the clearest evidence that local priv esc is treated as a foundational requirement while AD knowledge is optional at entry level. — [Junior Red Team Internship, EncryptEdge Labs](https://internships.encryptedgelabs.com/red-team-internship/)
- A Deloitte India red team manager role (Mumbai, 2025) requires: VAPT + Red Teaming experience, making no explicit distinction between local priv esc and AD attack skills in the listed requirements. — [T&T-Cyber-D&R-VAPT+Red Teaming-Manager-Mumbai, Deloitte](https://southasiacareers.deloitte.com/job/Mumbai-T&T-Cyber-D&R-VAPT%2BRed-Teaming-Manager-Mumbai/44049344)
- The Red Team Roadmap GitHub repository (soheilsec, widely referenced in 2024-2025 job prep discussions) groups "Active directory assessment" and "Post-exploitation techniques" as mid-level operator skills, developing concurrently rather than strictly sequentially. — [Red-Team-Roadmap, GitHub](https://github.com/soheilsec/Red-Team-Roadmap/blob/main/English.md)

### Inferences
- Job postings treat priv esc and AD exploitation as a bundle because they appear together in nearly every real engagement. Employers assume if you know one you likely know the other at some level.
- Junior/entry-level postings are the clearest signal: they expect priv esc knowledge but treat AD as a "nice to have," confirming that local priv esc is the more foundational of the two skills from a hiring manager's perspective.

### Gaps
- Direct access to live 2024-2026 LinkedIn and Indeed job postings was not possible in this research session due to network proxy restrictions. Findings from postings are based on search snippets and cached summaries rather than full job description text.
- India-specific job board data (Naukri.com, LinkedIn India) was not accessible. The Deloitte India result is the only India-specific data point found.

---

## Which skill do interviewers test first or consider more fundamental?

### Takeaway
Interview guides and community resources consistently present privilege escalation questions before Active Directory-specific questions in their structure, but the HadessCS Red Team Interview Questions repository (one of the most-cited community-curated lists) is an exception: it lists Active Directory at category 3 and Privilege Escalation at category 14, suggesting that AD knowledge is expected earlier in a red team interview conversation context.

### Cited Findings
- The HadessCS Red Team Interview Questions GitHub repository (60 categories, widely cited in 2024-2026 interview prep) lists category #3 as "Active Directory" and category #14 as "Privilege Escalation." Windows Network is category #2. The ordering places AD higher up as a topic expected to be discussed earlier in an interview, while standalone privilege escalation appears later in the list. — [Red-team-Interview-Questions, HadessCS GitHub](https://github.com/HadessCS/Red-team-Interview-Questions)
- The SSRN paper "Red Team Interview Questions" (Fazel Mohammad Ali Pour, 2024) covers: "initial access, privilege escalation, Active Directory attacks, malware development, and evasion techniques" in that stated topic order, placing privilege escalation before Active Directory attacks as a topic sequence. — [Red Team Interview Questions, SSRN](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=5164786)
- The Udemy course "500+ Red Teaming and Active Directory Interview Questions" (2024-2025) pairs AD and red teaming interview questions as one bundle, covering "Active Directory internals, enumeration, attack paths, privilege escalation techniques, and persistence strategies." AD internals appear as a required knowledge base before privilege escalation techniques are discussed within the AD context. — [500+ Red Teaming and Active Directory Interview Questions, Udemy](https://www.udemy.com/course/500-red-teaming-and-active-directory-interview-questions/)
- Community interview prep guides (InfoSecTrain, CyberInterviewPrep, 2024-2026) list "common privilege escalation techniques used in Red Team engagements, including exploiting vulnerable services, misconfigured permissions, kernel exploits, credential harvesting" as a distinct question category from Active Directory attacks like Kerberoasting, AS-REP Roasting, Golden Ticket, Pass-the-Ticket. — [Top 20 Red Team Interview Questions, InfoSecTrain](https://www.infosectrain.com/blog/interview-questions-for-red-team-expert); [Red Team Interview Questions (2026), CyberInterviewPrep](https://cyberinterviewprep.com/resources/red-team-interview-questions-2026)
- A SMBC Group Red Team Operator Associate interview report (secinterviews.com, 2025-2026) mentions that technical interviews probe "core tradecraft including an Active Directory attack path and a favorite privilege escalation technique," suggesting interviewers ask about both in the same session without a strict ordering preference. — [SMBC Group Red Team Operator Associate Interview, Security Interviews](https://secinterviews.com/smbc-group-sumitomo-mitsui-banking-corporation/red-team-operator-associate-interview-questions)

### Inferences
- There is no universal agreement on which skill interviewers test first. The most cited community question list (HadessCS) places AD earlier, while the academic SSRN paper places priv esc before AD in topic sequence.
- The practical interview evidence (SMBC report) suggests both are tested in the same session, with neither strictly preceding the other. Interviewers likely ask about whichever the candidate's CV emphasizes first.
- The consistent pairing of priv esc and AD in interview prep courses as a single product ("500+ Red Teaming and Active Directory Interview Questions") reflects that the market treats them as inseparable interview topics.

### Gaps
- No firsthand interview reports from Glassdoor were accessible that give a verbatim transcript or clear sequence of questions asked in a red team interview. All data is from curated prep guides, not candidate accounts.
- No India-specific interview reports were found.

---

## What do interview prep guides say about skill prerequisites?

### Takeaway
Interview prep guides universally describe a progression from local exploitation skills (including Windows privilege escalation) toward domain-level skills (Active Directory attacks), but they frame this as a learning sequence rather than stating that one must be achieved before the other is tested.

### Cited Findings
- Multiple 2024-2025 career roadmap resources describe the red team skill progression as: Reconnaissance → Initial Access → Execution and Evasion → Persistence and Privilege Escalation → Lateral Movement → Exfiltration. Active Directory exploitation sits within the Lateral Movement phase, placed after Privilege Escalation in the attack chain. — [Red Team Operator Career Path, CyberSecJobs](https://cybersecjobs.com/red-team-operator-career-path-cleared-professionals/); [Red Team Interview Questions (2026), CyberInterviewPrep](https://cyberinterviewprep.com/resources/red-team-interview-questions-2026)
- The "From Zero to Adversary" 2025 red teaming roadmap explicitly states: "Windows and Active Directory fundamentals for red teamers include local privilege escalation across common Windows misconfigurations" before "domain escalation, persistence, and post-exploitation." The guide emphasizes following the roadmap sequentially and mastering concepts before advancing. — [From Zero to Adversary, Medium (2025)](https://medium.com/@maverickcx64/from-zero-to-adversary-an-advanced-red-teaming-road-map-for-beginners-c3d2e52a1f9f)
- The CRTO LinkedIn review describes the course's learning sequence as: "initial access, lateral movement, local privilege escalation and persistence, credential theft, AD enumeration and exploitation, lateral movement and AD escalation." Local privilege escalation is explicitly positioned before AD enumeration and exploitation in the curriculum. — [Red Team Ops I (CRTO) Review, LinkedIn](https://www.linkedin.com/pulse/red-team-ops-i-crto-review-adversary-simulation-jake-mayhew)
- The SANS SEC565 Red Team Operations and Adversary Emulation course (2024-2025) lists its prerequisites as: "experience with penetration testing or administering Active Directory environments" AND "experience penetration testing Windows." These are stated as separate prerequisites, treating Windows penetration testing (which encompasses local priv esc) and Active Directory experience as distinct prior knowledge requirements. — [SEC565 Red Team Operations and Adversary Emulation, SANS](https://www.sans.org/cyber-security-courses/red-team-operations-adversary-emulation)

### Inferences
- The MITRE ATT&CK-based framing of the attack chain (used by most prep guides) naturally places Privilege Escalation (TA0004) before Lateral Movement (TA0008) and Discovery (TA0007), which are the tactics most associated with AD exploitation. This structural framing influences how prep guides sequence their content.
- Windows local priv esc is consistently treated as a post-initial-access, pre-lateral-movement skill, while AD attacks span lateral movement and privilege escalation within the domain, placing them conceptually after local priv esc.

### Gaps
- No prep guide explicitly states "you must know Windows local priv esc before studying Active Directory." The sequencing is implied by attack chain ordering, not stated as a formal prerequisite requirement.

---

## Do certifications (OSCP, CRTO, CRTE) sequence these skills, and does that match what employers want?

### Takeaway
OSCP explicitly covers local Windows privilege escalation as a foundational standalone module before its Active Directory attack modules. CRTP and CRTE focus on AD-specific attacks and are positioned as post-OSCP certifications. CRTO (Cobalt Strike operator tradecraft) assumes both priv esc and basic AD knowledge as prior skills. Employers asking for CRTO as a required certification implicitly expect priv esc knowledge as a prerequisite.

### Cited Findings
- OSCP (Offensive Security Certified Professional, 2024-2025 curriculum via PWK) covers: "Linux and Windows privilege escalation" as core modules alongside Active Directory attacks. The certification sequencing means candidates study and test on local priv esc before reaching the AD-focused sections. OSCP is widely described as the prerequisite to all AD-specialized certifications. — [Comprehensive OSCP Course Syllabus, Ethical Hacking Institute](https://www.ethicalhackinginstitute.com/blog/comprehensive-oscp-course-syllabus-full-pwk-training-breakdown-before-you-enroll)
- The recommended post-OSCP path for 2025-2026 (multiple sources, including India-market guides) is: OSCP → CRTP → CRTO. "OSCP provides the initial-access and pentest fundamentals that OSEP and CRTO both assume as baseline." CRTP teaches AD attack paths; CRTO teaches operational tradecraft with Cobalt Strike assuming prior AD knowledge. — [Best Certification After OSCP 2026, CertCrush](https://www.certcrush.app/blog/what-to-take-after-oscp-2026-osep-vs-crto-vs-crtp); [CRTO vs OSCP Honest Comparison 2026, Macksofy](https://www.macksofy.com/blog/crto-vs-oscp-honest-comparison-2026)
- CRTO explicitly requires AD knowledge before enrollment: "If Active Directory is new to you, you should wait before taking CRTO, as CRTO teaches adversary simulation with Cobalt Strike and assumes you already understand concepts like Kerberoasting." — [Best Certification After OSCP 2026, CertCrush](https://www.certcrush.app/blog/what-to-take-after-oscp-2026-osep-vs-crto-vs-crtp)
- CRTP (Certified Red Team Professional, Altered Security) is described as "cheap Active Directory attack depth" and is positioned as the AD foundation certification before CRTO. CRTE (Certified Red Team Expert) is described as "the natural step up within the same family" after CRTP, covering multi-forest AD attacks. The hierarchy is: CRTP (single-forest AD basics) → CRTE (multi-forest AD + persistence) → CRTO (Cobalt Strike OPSEC) → CRTL (engagement design). — [CRTP vs CRTE Altered Security Certs Compared, Macksofy](https://www.macksofytrainings.com/crtp-vs-crte-certification-guide-india-2026/); [Best Certification After OSCP 2026, CertCrush](https://www.certcrush.app/blog/what-to-take-after-oscp-2026-osep-vs-crto-vs-crtp)
- Senior red team operator job postings in the US cleared market list CRTO as a required certification and OSCP/OSCE/OSEE/GXPN/GPEN as preferred but not required. Since CRTO assumes both local priv esc and AD knowledge, requiring CRTO implicitly requires those foundational skills. — [Red Team Operator - Senior, BuiltIn](https://builtin.com/job/red-team-operator-senior/3531648)
- India market 2025-2026 guidance explicitly states that CRTP → CRTE → CRTO → CRTL is "the highest-ROI path for Indian offensive-security hiring." OSCP is recommended first, but some Indian candidates take CRTP before or without OSCP since CRTP's scope is narrower (AD only). — [After OSCP: 10 Next-Step Certifications for Indian Pentesters 2026, Macksofy](https://www.macksofytrainings.com/after-oscp-next-certifications-india-2026/)
- The SANS SEC565 (Red Team Operations) course content covers privilege escalation and Active Directory in a specific sequence: the fourth section of the course covers Active Directory domain enumeration, domain privilege escalation, Kerberos attacks, cross-domain lateral movement, and domain trust attacks. Prior sections cover initial access and non-AD post-exploitation skills. — [SEC565 Red Team Operations and Adversary Emulation, SANS](https://www.sans.org/cyber-security-courses/red-team-operations-adversary-emulation)

### Inferences
- Certification sequencing strongly confirms: Windows local priv esc (covered in OSCP) before AD exploitation (covered in CRTP) before AD + OPSEC tradecraft (covered in CRTO). Employers who require CRTO are hiring for a skill level that already encompasses both local priv esc and AD knowledge.
- The India-specific market diverges slightly: some practitioners skip OSCP and go directly to CRTP because the Indian job market values AD-specific certifications highly. This means local priv esc knowledge may be less formally validated in Indian hires compared to US/UK market hires who passed OSCP.

### Gaps
- The OSCP 2024-2025 specific module order (whether Windows priv esc module number appears before AD module number in the PWK course) was not confirmed with primary source access. Multiple secondary sources state both are covered, but the exact sequence within the course was not verifiable with the access available.

---

## What specific Windows priv esc techniques are listed in job requirements alongside AD skills?

### Takeaway
Job postings rarely list individual Windows priv esc techniques (such as token impersonation or SeImpersonate) by name. They use umbrella terms like "privilege escalation" and "lateral movement." The specific techniques appear in training materials and interview prep guides but not in job description text.

### Cited Findings
- No red team job postings from 2024-2026 were found that explicitly name "token impersonation," "SeImpersonatePrivilege," or "service misconfiguration" as requirements. Search results for these specific terms returned only technical documentation (MITRE ATT&CK T1134.001, blog posts, cheat sheets) and not job listings. — [Access Token Manipulation: Token Impersonation/Theft, MITRE ATT&CK](https://attack.mitre.org/techniques/T1134/001/)
- The Linode documentation on Windows Red Team Privilege Escalation Techniques (2024) documents specific techniques used in red team engagements: Unquoted Service Paths, DLL Hijacking, Weak Service Permissions, Token Impersonation, and Environment Variable Path Interception. These are the techniques red teamers are expected to know but they appear in training content, not in job posting requirements text. — [Windows Red Team Privilege Escalation Techniques, Linode Docs](https://www.linode.com/docs/guides/windows-red-team-privilege-escalation-techniques/)
- Job postings use language like "experience performing privilege escalation" or "Active Directory privilege escalation" without naming specific sub-techniques. The Packetlabs posting is representative: "privilege escalation, Active Directory security assessments, and lateral movement testing" as umbrella categories. — [Penetration Tester – Infrastructure, Red Team at Packetlabs via RemoteRocketship](https://www.remoterocketship.com/us/company/packetlabs-net-2/jobs/penetration-tester-infrastructure-red-team-united-states-remote/)
- The CRTO curriculum (from LinkedIn review, 2024-2025) explicitly covers specific AD privilege escalation techniques as distinct from local priv esc: Kerberoasting, AS-REP Roasting, Golden Ticket attacks, Pass-the-Ticket, NTLM relay, LDAP relay, LLMNR poisoning, and domain trust attacks. These are the AD-specific techniques that interviewers test once local priv esc knowledge is assumed. — [Red Team Ops I (CRTO) Review, LinkedIn](https://www.linkedin.com/pulse/red-team-ops-i-crto-review-adversary-simulation-jake-mayhew)
- The Bishop Fox 2025 Red Team Tools report notes that BloodHound is now a standard requirement, described as a tool "built to extract relationship data needed to map privilege escalation paths and lateral movements in a network." BloodHound knowledge is the closest thing to a named-tool requirement that bridges local priv esc and AD enumeration in job market discussions. — [Top Red Team Tools & C2 Frameworks for 2025, Bishop Fox](https://bishopfox.com/blog/2025-red-team-tools-c2-frameworks-active-directory-network-exploitation)

### Inferences
- The absence of named techniques in job postings is intentional: employers want operators who understand the category of attack, not just specific tools. Naming specific techniques in a job posting would make requirements too narrow and age quickly as techniques evolve.
- In interviews, specific technique knowledge is tested verbally. The SMBC interview report and community guides confirm that "describe your favorite privilege escalation technique" is a common interview question, where the expected answer might include token impersonation, service misconfigs, or registry-based priv esc.

### Gaps
- No confirmed verbatim job posting text listing specific local priv esc technique names (token impersonation, SeImpersonate, unquoted service paths) alongside AD skills was found. The proxy restrictions prevented direct access to job boards.
- No data on whether specific technique requirements differ between US/UK market and India/global market was found.
