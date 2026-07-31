Summary

Produce a written proposal for the Fake Company project — a synthetic enterprise environment populated by AI agents that serves as (a) a firing range for adversary simulation and (b) a benign background-noise generator for detection development. The proposal should be detailed enough that the team can decide whether to commit engineering capacity, and structured enough that it can be shared with stakeholders outside Threat Research.

The PRD in Notion (Fake Company) captures the current shape of the idea. This task is to turn it into a decision-ready proposal.

Scope

Vision and value proposition

Problem framing: why synthetic security telemetry is hard (referencing prior art — OrgForge-IT paper, Emergence World, TinyTroupe, Dylan Williams' post).

Value to Panther specifically:

Detection engineers get a continuously-running source of identity + SaaS + cloud telemetry with ground truth for both benign and malicious activity, enabling precision/recall measurement of new and existing rules.

Internal benchmark for the Panther MCP — a synthetic SOC analyst driven by the MCP is a continuous-integration test for the agentic surface.

Reusable substrate for red-team-style content development, customer demos, and onboarding.

Adjacent value: heterogeneous-model agent population produces behavioral variance that single-vendor synthetic data can't.

Scope: v1 vs. v2

v1 — identity + SaaS + cloud firing range. API-only agent activity. Log sources: Okta, Google Workspace, AWS (CloudTrail), GitHub. Panther instance ingests everything. No per-employee VMs, no EDR, no browser automation.

v2 — endpoint expansion. Per-employee VMs (or equivalent), EDR (likely CrowdStrike or SentinelOne for customer realism), browser automation for the workflows where it matters, endpoint-flavored chaos and red-team TTPs.

Explicit non-goals for v1: realistic email/Slack message content quality, real video calls, USB/printer telemetry.

Architecture

Agent substrate: model-agnostic framework (LangGraph / Pydantic AI / custom loop) with multi-vendor inference routing (OpenRouter or direct SDKs). Replaces the OpenClaw/Claude-managed framing in the original PRD draft.

Compute: 2–3 small EC2 instances hosting containerized agents, grouped by function (eng host / ops host / office host) so source IPs cluster realistically and produce per-team identity signals.

Per-agent persistent state: named Docker volumes, with the agent itself writing diary and work artifacts to its own Google Drive folder (user-attributed, generates realistic SaaS telemetry). Sidecar rclones the non-user-attributed state (episodic SQLite, vector store, agent state) to a system-owned Drive folder for backup.

MCP servers for each SaaS surface (Slack, GitHub, Workspace, Atlassian, Okta, AWS, Panther). Inventory and gap-analysis required — note which are official / community / need to be wrapped. Source-IP attribution must be preserved; reject MCP servers that proxy through their own infra for load-bearing roles.

Credentials: every agent has its own service account / OAuth credential per SaaS, provisioned by the IT agent through real Okta and Workspace flows. No shared service accounts — the provisioning events themselves are part of the telemetry.

Org chart (v1 headcount: 6–10 agents)

CEO — strategic direction, light activity.

IT — Okta and Workspace administration, ticket queue, credential provisioning, chaos remediation.

Security — Panther MCP-driven triage and investigation; primary internal test of the Panther agentic surface.

Engineering (2–3) — build/deploy the small AWS-hosted app that serves as the chaos surface; commit to GitHub, manage AWS infra.

Marketing / generic employee (1–2) — Workspace-heavy activity for noise diversity.

Chaos gremlin — separate agent with host-level/infra-level access to inject faults and config drift (IAM policy changes, credential rotation, sharing misconfig, deploy failures, etc.). Operates outside the regular org structure.

The "thing that gets built"

A small internal web app deployed to AWS (ECS or similar), with engineers committing code via GitHub, CI deploying, IT managing the AWS account, Security monitoring. This produces CloudTrail, GitHub audit logs, deploy events, and gives the gremlin a real surface to break. Specify the IAM model, repo layout, and deploy path in the proposal.

Chaos gremlin design

Fault catalog split into security-relevant (IAM drift, exposed S3, OAuth scope expansion, MFA disabled on a service account) and security-irrelevant (cert expiring, deploy failure, disk full). Both kinds matter — pure-security faults teach detections that every alert is real, which isn't a realistic noise profile.

Ground-truth event log: every gremlin action recorded separately so detection coverage can be measured.

v1 restricted to API-reachable surfaces.

Adversary simulation / needle injection

Three options to choose between in the proposal:

Scripted attacks on a schedule (most repeatable, best for rule regression).

Autonomous red-team agent (most realistic, hardest to constrain — blast-radius concerns).

Hybrid: scripted TTPs with agent-driven variation in timing, target, and pivot path.

Recommend option 3 for v1, with red-team substrate isolated from company agents (different credentials, different framework).

Cost estimates

Back-of-envelope to support the decision:

Infrastructure: 2–3 t3.small EC2 ≈ $45/mo, EBS + data transfer ≈ $10–20/mo.

LLM API costs: dominant variable cost. Estimate per-agent-per-day token spend across roles, then scale to v1 headcount × continuous operation. Include cost of model heterogeneity (some routes through more expensive models).

SaaS: Okta dev tenant, Workspace seats (one per agent), GitHub org, AWS account already exists. Quantify per-seat costs where applicable.

Engineering time: estimate v1 build effort (FTE-weeks) including substrate, container layout, MCP integration, chaos gremlin, ground-truth logging, initial agent personalities.

v2 incremental cost: VMs (10× t3.medium minimum), EDR licenses, additional engineering for browser automation and endpoint chaos.

Success criteria

v1: a detection engineer can take an existing Panther rule, run it against the fake company's last 30 days of logs, and get a precision/recall number they trust. The ground-truth event log makes this measurable.

v2: same, extended to endpoint-flavored detections.

Risks and open questions

LLM cost overrun on continuous operation.

Agent behavioral instability (Emergence World's "phase transition" finding — populations either lock in or collapse). Mitigation: tight role scripts, deterministic-replay mode.

MCP server reliability for load-bearing roles (Security agent's Panther MCP, IT agent's Okta workflow). Mitigation: self-host, pin versions, smoke-test daily.

Source IP attribution if any MCP server proxies through hosted infra.

Determinism / replay for detection regression testing — needs explicit design.

Scope creep into "behavioral simulation" (Emergence-style) when the actual goal is detection telemetry.

Comparison to prior art

Brief positioning against:

Emergence World — studies agents as the object of interest; we study detections.

TinyTroupe — simulation framework, useful reference but not detection-oriented.

OrgForge-IT — closest analog; reference its methodology where relevant.

dev.to AI Company — cautionary tale on memory architecture and operational discipline.

Deliverable

A written proposal document (Notion page, expanding the existing PRD) containing all sections above, plus a recommended v1 scope and timeline. Long enough to be decision-ready, short enough that stakeholders will read it (target: 4–8 pages equivalent).

Acceptance Criteria

Proposal published as a Notion page (expanding or replacing the current PRD draft).

v1 scope is explicit and defensibly narrow (identity + SaaS + cloud, no endpoint).

Cost estimate includes infrastructure, LLM API, SaaS seats, and engineering FTE-weeks for v1; v2 incremental cost stated separately.

Value proposition is grounded in concrete Panther use cases (detection development, MCP benchmarking, demos), not generic "synthetic data is useful."

Org chart, headcount, and role responsibilities specified.

Chaos gremlin fault catalog drafted (not exhaustive, but enough to show the shape).

Needle-injection / red-team model selected with rationale.

Success criteria are measurable.

Risks section names the top 3–5 with mitigations.

Reviewed by at least one Threat Research team member before being shared more broadly.

References

Parent epic: THREAT-721 — Fake Company

PRD: Notion — Fake Company

Emergence World blog post

dev.to — I Built a Company Run Entirely by AI Agents

OrgForge-IT paper (arXiv)

TinyTroupe

Dylan Williams — synthetic enterprise telemetry post

