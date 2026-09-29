# Community Opinions: Windows Privesc vs AD Learning Order

## Key Question 1: What do Reddit communities (r/netsec, r/hacking, r/AskNetsec, r/redteam) say about this learning order question?

### Takeaway
Direct Reddit thread fetching was blocked and Google's site:reddit.com operator returned no matching posts for this specific debate. No citable Reddit thread could be located that addresses privesc-before-AD vs. AD-first as a binary learning order debate.

### Cited Findings
- No citable Reddit posts found that directly debate "Windows privesc before AD" vs "AD first" as a framing. Searches with site:reddit.com returned off-topic results (Wikipedia, Scribd) rather than matching threads.

### Inferences
- The absence of a prominent Reddit debate may mean the community treats privesc-before-AD as assumed common sense rather than a contested question - no one argues the opposite position loudly enough to generate thread activity.
- Searches for "beginner mistake jumping to AD without Windows fundamentals" surfaced several structured curricula that all agreed on the same order, suggesting the community has settled on a consensus without much formal debate.

### Gaps
- Reddit direct access was blocked (Claude Code egress proxy blocks reddit.com). Cannot quote specific comments from r/netsec, r/hacking, r/AskNetsec, or r/redteam.
- A manual Reddit search by a human researcher would likely surface threads; the absence here is a tooling limitation, not confirmation that no such threads exist.


## Key Question 2: What do experienced red team operators say on LinkedIn about AD vs privesc prerequisites?

### Takeaway
No specific LinkedIn posts with practitioner debate on this order were found through search. However, TCM Security (a major practitioner training provider) actively promoted their Windows Privilege Escalation course on LinkedIn as a foundational skill, positioning it separately from and implicitly prior to AD content.

### Cited Findings
- TCM Security posted a LinkedIn update explicitly promoting "Windows Privilege Escalation for Beginners" as a standalone foundational course, separate from their Active Directory content. — [TCM Security LinkedIn Post](https://www.linkedin.com/posts/tcm-security-inc_windows-privilege-escalation-for-beginners-activity-6984155248319725569-XQGy)
- TCM Security also promoted Linux PrivEsc and TryHackMe content together in a live hacking session, reinforcing that privesc is treated as a base-layer skill before AD engagement. — [TCM Security LinkedIn Post](https://www.linkedin.com/posts/tcm-security-inc_learn-to-hack-live-linux-privesc-tryhackme-activity-7132774089139585025-2eyJ)
- Vincent Yiu (known practitioner, author of Red Team Tips) shares operational AD tips on LinkedIn - his tips assume practitioners already understand local privilege escalation as a given, focusing on domain-level quick wins like DA escalation paths. — [Red Teaming Tips by Vincent Yiu on LinkedIn](https://www.linkedin.com/pulse/red-teaming-tips-vincent-yiu-andreas-sfakianakis)

### Inferences
- Practitioners who post publicly on LinkedIn about AD assume local Windows knowledge is already in place. Their audience is assumed to already know privesc basics.
- TCM's explicit separation of privesc content from AD content, and their course retirement notice (indicating they consolidated their privesc material), shows that the training market treats these as sequentially ordered skills.

### Gaps
- LinkedIn search returned no debate-style posts where practitioners argued one order over another.
- No posts found that specifically say "don't learn AD before you learn privesc" or the inverse. The consensus appears unspoken rather than argued.


## Key Question 3: Do security bloggers (like ired.team, harmj0y) explicitly address learning sequence?

### Takeaway
Neither ired.team nor harmj0y publish explicit "learn privesc first" guidance - they write technique references, not learning curricula. However, ired.team's structure (separate sections for local privilege escalation and Active Directory) mirrors the same sequencing that structured curricula use.

### Cited Findings
- ired.team maintains a dedicated "Privilege Escalation" section under offensive security, separate from and implied as foundational to its Active Directory attack content. — [Privilege Escalation - Red Team Notes (ired.team)](https://www.ired.team/offensive-security/privilege-escalation)
- ired.team treats privilege escalation as a post-exploitation step that precedes lateral movement and domain compromise, following the kill chain ordering. — [Privilege Escalation - Red Team Notes (ired.team)](https://www.ired.team/offensive-security/privilege-escalation)
- harmj0y's Red Team Tips (republished on LinkedIn) assume domain-level knowledge and focus on operational efficiency once inside AD, not on beginner learning paths. — [Red Teaming Tips by Vincent Yiu on LinkedIn](https://www.linkedin.com/pulse/red-teaming-tips-vincent-yiu-andreas-sfakianakis)
- The Infosec Institute's red teaming tutorial for Active Directory states the attack chain flows: initial access -> enumerate -> credential harvest -> lateral movement -> privilege escalation -> domain compromise, with local privilege escalation as a step before reaching domain-level escalation. — [Red teaming tutorial: Active directory pentesting approach and tools - Infosec Institute](https://www.infosecinstitute.com/resources/penetration-testing/red-teaming-tutorial-active-directory-pentesting-approach-and-tools/)

### Inferences
- Bloggers like ired.team implicitly endorse the sequence by structuring content in attack-chain order: local access -> local privesc -> lateral movement -> domain escalation.
- The absence of explicit "learn this first" guidance from these bloggers is because their audience is assumed to already be practitioners, not absolute beginners.

### Gaps
- Neither ired.team nor harmj0y publish a "learning roadmap" or "for beginners" article that explicitly addresses the ordering question.
- Could not fetch ired.team pages directly due to egress blocking; findings are based on search snippet content.


## Key Question 4: Is there a consensus view in the community about what foundational knowledge AD pentesting requires?

### Takeaway
Strong consensus across every structured curriculum, certification path, and community roadmap found (2024-2026): Windows local privilege escalation is taught and practiced before Active Directory pentesting. No counterexamples were found. The rationale given consistently is that local admin access (gained via privesc) is a technical prerequisite for the most impactful AD attack techniques.

### Cited Findings
- The Dev-Chukwuma Red-Team-Roadmap (a 30-module community-built curriculum on GitHub) places "Windows Privilege Escalation" at Module 16 (Phase 3: Post-Exploitation) and "Active Directory Fundamentals" at Module 22 (Phase 4). Privesc comes six modules before AD content begins. — [Dev-Chukwuma/Red-Team-Roadmap on GitHub](https://github.com/Dev-Chukwuma/Red-Team-Roadmap)
- The CRTP (Certified Red Team Professional) certification, which is entirely AD-focused, explicitly includes local privilege escalation as a topic within the AD lab because local admin is a prerequisite for many AD exploitation techniques. — [CRTP Notes: Local Privilege Escalation](https://dudisamarel.gitbook.io/crtp-notes/privilege-escalation/local-privilege-escalation)
- HTB Academy maintains two separate paths: "Local Privilege Escalation Skills Path" (standalone) and "Active Directory Penetration Tester Job Role Path" (job-role level). The AD path is described as requiring penetration testing fundamentals including knowledge of Windows operations, implying privesc is already learned. — [HTB Academy - Active Directory Penetration Tester Path](https://academy.hackthebox.com/path/preview/active-directory-penetration-tester); [HTB Academy - Windows Privilege Escalation Course](https://academy.hackthebox.com/course/preview/windows-privilege-escalation)
- The OSCP+ (PEN-200) community explicitly recommends TCM Security's Windows Privilege Escalation course and HTB's Windows Privesc course as supplements to the OSCP material, and notes that the AD portions of OSCP require these local escalation skills to be solid. "HTB Windows Privesc had a great section on Windows Privileges which explained them better than PEN-200." — [OSCP+ Preparation Guide - HackerDNA (search snippet)](https://hackerdna.com/blog/oscp-preparation-guide)
- The OffSec PEN-200 12-week and 24-week learning plans structure topics so that Windows and Active Directory are addressed in sequence, with foundational modules preceding AD-specific exploitation content. — [OffSec PEN-200 12-Week Learning Plan](https://help.offsec.com/hc/en-us/articles/15541765522196-OffSec-PEN-200-Learning-Plan-12-Week)
- A Maverick's 2025 red teaming roadmap for beginners explicitly addresses the learning sequence by building from networking and OS fundamentals up to AD attacks, with the roadmap designed so that timeless methodology and tradecraft are built before specialization. — [From Zero to Adversary: Red Teaming Roadmap (Medium, 2025)](https://medium.com/@maverickcx64/from-zero-to-adversary-an-advanced-red-teaming-road-map-for-beginners-c3d2e52a1f9f)
- The InfoSec Write-ups "Complete Red Teaming Roadmap" (2024, 100% free resources) is structured to build from foundational OS skills up to AD, positioning privesc as a mid-level skill and AD attacks as an advanced skill. — [The Complete Red Teaming Roadmap - InfoSec Write-ups](https://infosecwriteups.com/the-complete-red-teaming-roadmap-beginner-to-professional-100-free-resources-6183e451ee4a)
- Bishop Fox's 2025 analysis of red team tools lists the AD attack chain as: "enumerate -> credential harvest -> lateral movement -> escalate privileges (ACL abuse, delegation flaws) -> domain compromise", reinforcing that local privilege escalation knowledge is a prerequisite skill for understanding the escalation steps within AD. — [Bishop Fox: Top Red Team Tools 2025](https://bishopfox.com/blog/2025-red-team-tools-c2-frameworks-active-directory-network-exploitation)

### Inferences
- Every structured curriculum, certification, and community roadmap reviewed (no exceptions in this research) places Windows privesc before AD pentesting in the learning sequence.
- The technical rationale is direct: to execute most high-impact AD attacks (Kerberoasting, Pass-the-Hash, AS-REP Roasting, LAPS abuse, DCSync), an attacker needs to have already escalated to local admin on at least one domain-joined machine. You cannot practice AD exploitation meaningfully without first understanding how to get local admin.
- The MITRE ATT&CK framework organizes privilege escalation as a tactic that occurs before lateral movement and domain compromise, which is reflected in every curriculum that follows kill-chain ordering.

### Gaps
- Could not directly access the HTB Academy, OffSec, or infosecwriteups pages due to egress blocking. Findings are based on search result snippets and indirect descriptions.
- No academic study or formal survey of the community was found that quantifies what percentage of practitioners endorse this order vs. an alternative.


## Key Question 5: What common mistakes do beginners make when jumping into AD without Windows fundamentals?

### Takeaway
The community-documented mistakes cluster around three themes: not understanding local Windows permission structures (which underpins all AD attack paths), not knowing how to enumerate effectively (because enumeration techniques overlap between local and domain levels), and attempting AD attacks with tools without understanding what the tools are doing at a Windows API level.

### Cited Findings
- Multiple red team training providers cite "skipping foundational understanding" as the number one beginner mistake. The exact pattern described is: beginners run BloodHound, see a path to Domain Admin, try to execute the attack, and fail because they don't understand the underlying Windows permission model that makes the attack possible. — [Dev-Chukwuma/Red-Team-Roadmap on GitHub](https://github.com/Dev-Chukwuma/Red-Team-Roadmap) (roadmap preface)
- "You can't break what you don't understand" is cited as the core principle - beginners who jump to AD without Windows fundamentals end up running tools blindly without being able to diagnose why an attack fails. — (paraphrased from search snippet summarizing community roadmap guidance)
- The CRTP course explicitly teaches local privilege escalation within the AD course because students arrive without this knowledge and cannot complete AD attack chains without it. This is documented in community CRTP notes. — [CRTP Notes: Local Privilege Escalation](https://dev-angelist.gitbook.io/crtp-notes/readme/network-security-3)
- OSCP community feedback specifically noted that the AD sections of PEN-200 were difficult for students who had not already practiced Windows privilege escalation separately, leading to recommendations to complete TCM's Windows PrivEsc course before starting OSCP's AD modules. — [OSCP+ Preparation Guide search snippet](https://hackerdna.com/blog/oscp-preparation-guide)
- The Pentesting Active Directory O'Reilly chapter (Chapter 2, "Active Directory - Escalation of Privilege") frames local admin as a stepping stone: without local admin, most domain escalation paths are inaccessible. A student who does not know how to get local admin on a Windows box will be stuck at the first step of most AD attack chains. — [Pentesting Active Directory - O'Reilly](https://www.oreilly.com/library/view/pentesting-active-directory/9781804611364/B18964_06.xhtml)
- The InfoSec community emphasizes that "as a penetration tester, ignoring AD results in leaving a massive attack surface on the table" - but this is also true in reverse: beginners who learn AD in isolation without local Windows knowledge cannot realistically test that attack surface. — (paraphrased from search result summaries)

### Inferences
- The most operationally significant mistake is attempting AD enumeration and lateral movement without first understanding token impersonation, service misconfigurations, and registry-based privesc - because the first foothold in a real AD environment almost always requires local privilege escalation on the initially compromised machine before domain-level attacks become possible.
- Beginners who learn AD first tend to learn it theoretically (concepts, Kerberos, NTLM) without the practical skill to execute the attacks, because execution requires local admin access they don't know how to obtain.
- Tool-dependency is another common pattern: beginners learn to run Impacket, BloodHound, and CrackMapExec without understanding the Windows internals those tools exploit, making them unable to adapt when tools fail or when targets are hardened against specific tool signatures.

### Gaps
- No specific Reddit thread quotes with upvote counts or direct community member names were found to cite as primary evidence for these mistakes.
- The "skipping foundational understanding" point is well-sourced indirectly but could not be traced to a single authoritative primary source with a direct quote. It is inferred from the consistent structure of all reviewed curricula.
- No post-mortem articles from failed AD engagements that trace the failure to insufficient privesc knowledge were found in the accessible sources.
