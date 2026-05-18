# Newsletter Review Queue

## April 2026 Draft

### Manual Decisions Needed

- Title: April 2026 Videos section shortfall
  - URL: See `video_evidence.md`
  - Proposed section: Videos
  - Original date / evidence: April 2026 target issue; YouTube evidence collected with `yt-dlp`
  - Period status: missing_evidence
  - Issue / reason: The strict video gate found no videos that simultaneously met official cybersecurity conference talk, direct AI-security relevance, April 2026 upload/publication, known duration, and 20+ minute duration. The draft does not pad with May uploads, podcasts, tutorials, vendor clips, or generic cybersecurity videos.
  - Suggested action: Leave Videos empty for April, or approve a deliberate exception such as carrying May-uploaded SANS/CSA AI security conference recordings into a future issue.

- Title: Careful Adoption of Agentic AI Services
  - URL: https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/
  - Proposed section: Reports
  - Original date / evidence: NSA guidance listing shows 4/30/2026; other public sources report May 1, 2026 release.
  - Period status: carryover_candidate
  - Issue / reason: Strong non-vendor government guidance for agentic AI security, but the publication date straddles the April/May issue boundary.
  - Suggested action: Prefer May 2026 unless you explicitly want to treat the NSA 4/30 listing date as April evidence.

### May Video Candidates Excluded From April

- Title: Keynote: Cramhole, LaFleur: Indirect Prompt Injection
  - URL: https://www.youtube.com/watch?v=3Br2xJZR3mI
  - Proposed section: Videos
  - Original date / evidence: YouTube upload date 2026-05-04; duration 24m 37s; channel SANS Institute.
  - Period status: out_of_period
  - Issue / reason: Strong SANS AI Cybersecurity Summit video, but uploaded in May, not April.
  - Suggested action: Consider for the May 2026 issue.

- Title: Enterprise MCP and Agent Security Reference Architectures
  - URL: https://www.youtube.com/watch?v=hK20QMhZwTE
  - Proposed section: Videos
  - Original date / evidence: YouTube upload date 2026-05-04; duration 28m 57s; channel Cloud Security Alliance (CSA).
  - Period status: out_of_period
  - Issue / reason: Strong Agentic AI Summit video, but uploaded in May, not April.
  - Suggested action: Consider for the May 2026 issue.

- Title: Prompts to Production - Building Effective Security Automation For Everyone #BSidesBUD2026
  - URL: https://www.youtube.com/watch?v=xNXsh0pHB4w
  - Proposed section: Videos
  - Original date / evidence: YouTube upload date 2026-05-11; duration 40m 10s; channel BSides Budapest IT Security Conference.
  - Period status: out_of_period
  - Issue / reason: AI/security automation talk from a cybersecurity conference, but uploaded in May.
  - Suggested action: Consider for the May 2026 issue if the topic fits the final May editorial mix.

### Excluded Video Candidates

- Title: UniCon 2026: Continuous Validation in the Age of AI
  - URL: https://www.youtube.com/watch?v=2HpcD9oXaEs
  - Proposed section: Videos
  - Original date / evidence: YouTube upload date 2026-04-09; duration 6h 18m 48s; channel SCYTHE.
  - Period status: invalid_video_source
  - Issue / reason: April-uploaded, but vendor-run full event recording rather than a specific official cybersecurity conference talk.
  - Suggested action: Keep excluded unless you explicitly allow vendor-run event recordings.

- Title: 2026 FIRST CTI Conference - Day 1 Plenary Sessions - Live Stream
  - URL: https://www.youtube.com/watch?v=-9GbyvoktXc
  - Proposed section: Videos
  - Original date / evidence: YouTube upload date 2026-04-22; duration 8h 05m 36s; channel FIRST.
  - Period status: invalid_video_source
  - Issue / reason: Official cybersecurity conference livestream, but not a specific AI-security talk and too broad for the newsletter's technical AI security promise.
  - Suggested action: Keep excluded unless a specific AI-security segment with timing/source evidence is identified.

### Vendor Reports Excluded Completely

- Title: HiddenLayer, Rapid7, Cisco, Tenable, OpenAI, Anthropic, Microsoft, Google, IBM, and other commercial vendor "state of" / threat landscape / survey reports
  - URL: Multiple vendor pages
  - Proposed section: Reports
  - Original date / evidence: April 2026 source review
  - Period status: invalid_vendor_report
  - Issue / reason: Reports section is non-vendor only. Obvious vendor reports were excluded completely and were not used to fill shortfalls.
  - Suggested action: Keep excluded unless a specific vendor-originated item is actually a technical vulnerability writeup rather than a report.
