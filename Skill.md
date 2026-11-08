---
name: enterprise-payroll-automation
version: 1.0.0
description: >-
  Compliance-first payroll process automation. Orchestrates batch payroll (multi-state tax,
  overtime, bonuses, garnishments, 401(k)), anomaly detection with human-in-the-loop review and
  encrypted payslip delivery, and exposes it to enterprise LLMs over MCP.
author: Enterprise AI Platform Team <ai-platform@acme-corp.example>
license: Proprietary – internal use
status: stable
compliance_basis: reference/compliance_rules.md (FY2026 MOCK rules – not tax advice)
---

# Enterprise Payroll Process Automation

## 1. Metadata

| Field | Value |
|---|---|
| Skill name | `enterprise-payroll-automation` |
| Version | **1.0.0** ([Semantic Versioning](https://semver.org)) |
| Versioning policy | MAJOR: breaking change to tool schemas or `PayrollResult`; MINOR: new tool/capability or compliance table year; PATCH: bug fixes, rule corrections with no schema change |
| Owner | Enterprise AI Platform Team (escalation: payroll-oncall@acme-corp.example) |
| Runtime | Python ≥ 3.11, LangGraph ≥ 1.0, Pydantic v2, MCP Python SDK ≥ 1.12 |

### Service-level objectives (design targets; verify in your environment)

| SLO | Target |
|---|---|
| Availability (MCP endpoint) | 99.9 % monthly |
| Latency, batch ≤ 50 employees, no HITL | p95 ≤ 5 s end-to-end (mock backends: < 1 s) |
| Latency, guardrail rejection | p95 ≤ 100 ms |
| Calculation accuracy vs. manual | 100 % (deterministic `Decimal` math; any deviation is a Sev-2) |
| Human review turnaround (business hours) | ≤ 4 h from interrupt to decision |
| RPO / RTO (with a durable checkpointer) | ≤ 5 min / ≤ 15 min |
| PII exposure in logs, state snapshots and tool output | 0 raw SSNs / account numbers |

## 2. Capabilities and boundaries

### Supported tasks
- **Batch payroll** for explicit employee ids and/or a department + state filter (e.g. "NY marketing team").
- **Multi-region tax computation**: federal brackets, FICA (Social Security wage base, Medicare, Additional Medicare), CA / NY / TX state rules, CA & NY SDI.
- **Overtime**: federal weekly, **California daily (1.5× / 2×)**, Texas weekly-only.
- **Bonus handling**: percentage and fixed bonuses, supplemental withholding (22 % / 37 % over $1M, state supplemental rates).
- **Deductions**: health (Section 125), 401(k) elective deferral with annual-limit logic and "maxed" requests.
- **Garnishments**: CCPA creditor limits and child-support limits with combined cap.
- **Proration** for mid-cycle hires or explicit effective dates.
- **Anomaly detection and HITL**: confidence < 0.85, period-over-period variance > $10,000, tax rate outside 5–55 %.
- **Secure payslip delivery** (simulated encrypted PDF over enterprise SMTP) to corporate mailboxes only.
- **Unstructured HR queries** parsed into a whitelisted, schema-validated intent (rules, optionally an LLM).

### Anti-goals (never performed; requests are rejected, not queued)
| Anti-goal | Enforcement |
|---|---|
| Executing bank transfers / ACH / wires or any money movement | Guardrail `FUNDS_MOVEMENT`; no such tool exists |
| Changing salary, rates, elections or bank details | Guardrail `SALARY_MUTATION`; HRIS access is read-only; adjustment kinds are a closed whitelist |
| DDL/DML or destructive operations on systems of record | Guardrail `DESTRUCTIVE_DATA_OPERATION` |
| Sending data to non-corporate recipients | Guardrail `EXTERNAL_RECIPIENT` / `DATA_EXFILTRATION`; delivery domain allow-list |
| Bulk disclosure of SSNs / bank data | Guardrail `PII_EXFILTRATION`; only masked identifiers cross agent boundaries |
| Skipping review, four-eyes or role checks | Guardrails `CONTROL_BYPASS`, `PRIVILEGE_ESCALATION`; reviewer ≠ requester enforced |
| Real tax/legal advice or non-FY2026-mock rates | Out of scope; every figure cites `compliance_rules.md` |

### Role-based access
| Role | Run payroll | Executive records | Resume review | Read run state |
|---|---|---|---|---|
| `PAYROLL_ADMIN` | ✔ | ✔ | ✔ (≠ requester) | ✔ |
| `HR_MANAGER` | ✔ | ✘ | ✔ (≠ requester) | ✔ |
| `AUDITOR` | ✘ | ✘ | ✘ | ✔ (redacted) |
| `EMPLOYEE` | ✘ | ✘ | ✘ | ✘ |

> The MCP payload's `role` is a *claim*. In production bind identity to the authenticated principal
> (OAuth / mTLS at the transport) or pin it per deployment with `MCP_FORCE_ROLE`.

## 3. MCP configuration

| Setting | Value |
|---|---|
| Server name / version | `payroll-automation` / `1.0.0` |
| Protocol revision | `2025-06-18` (SDK negotiates down to the client's supported revision) |
| Message format | JSON-RPC 2.0 |
| Transports | **stdio** (default; Claude Desktop, local agents) · **SSE** (`--transport sse`, remote clients) · streamable-HTTP (`--transport streamable-http`) |
| Entry point | `python scripts/mcp_server.py --transport stdio` |
| Logging | structured JSON on **stderr** (stdout is the stdio channel) |

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "payroll-automation": {
      "command": "python",
      "args": ["scripts/mcp_server.py", "--transport", "stdio"],
      "env": { "LOG_LEVEL": "INFO", "HRIS_DB_URI": "postgresql://payroll_ro:***@hris.internal:5432/hris" }
    }
  }
}
```

### Exposed surface

| Kind | Name | Purpose |
|---|---|---|
| tool | `run_payroll(request: RunPayrollRequest)` | Start a run from a nested payload |
| tool | `resume_human_review(thread_id, approved, reviewer, note?)` | Resume a run paused at HITL |
| tool | `get_run_state(thread_id, role?)` | PII-redacted snapshot from the checkpointer |
| resource | `payroll://compliance/rules` | The compliance manual (grounding source) |

`tools/call` request for `run_payroll`:

```json
{
  "jsonrpc": "2.0", "id": 7, "method": "tools/call",
  "params": {
    "name": "run_payroll",
    "arguments": {
      "request": {
        "requester": { "requester_id": "alice@acme-corp.example", "role": "PAYROLL_ADMIN" },
        "batch": { "emp_ids": ["EMP019"], "department": "Marketing", "state": "NY" },
        "adjustments": [
          { "emp_id": "EMP042", "kind": "bonus_pct", "value": "15" },
          { "emp_id": "EMP019", "kind": "max_401k" },
          { "emp_id": "EMP007", "kind": "prorate", "effective_date": "2026-11-02" }
        ],
        "notes": "Process batch payroll for the NY marketing team.",
        "options": { "thread_id": "pay-2026-11-13-ny-mkt" }
      }
    }
  }
}
```

Schema summary (strict: unknown fields are rejected):

| Object | Field | Type / constraint |
|---|---|---|
| `requester` | `requester_id` | string 1–128 |
| | `role` | `PAYROLL_ADMIN` \| `HR_MANAGER` \| `AUDITOR` \| `EMPLOYEE` |
| `batch` | `emp_ids` | `EMP###` ids (≤ 500) |
| | `department`, `state` | optional; `state` ∈ {CA, TX, NY} |
| `adjustments[]` | `emp_id` | `EMP###` |
| | `kind` | `bonus_pct` (0–100] \| `bonus_amount` (≤ 5,000,000) \| `max_401k` \| `prorate` |
| | `value`, `effective_date` | decimal / ISO date per kind |
| `notes` | | free text ≤ 2000 chars (guardrail-screened) |
| `options` | `thread_id`, `period_start` | `^[A-Za-z0-9_.-]{4,64}$`; Monday ISO date |

Successful result: a redacted run snapshot (`status`, `paused_for_review`, `interrupt`, `results[]` as
`PayrollResult`, `summary`, `audit_trail`, `errors`).

### Error contract (JSON-RPC `error.code`)

| Code | Name | Raised when |
|---|---|---|
| -32602 | Invalid params | Schema violation, or no employee scope could be determined |
| -32001 | Not found | Unknown employee (batch dead-lettered) or unknown `thread_id` |
| -32002 | Upstream unavailable | HRIS unreachable after retries (retryable) |
| -32003 | Forbidden | Guardrail rejection, RBAC denial, four-eyes or policy violation |
| -32004 | Unprocessable | Calculation anomaly (e.g. net > gross) |
| -32603 | Internal error | Anything unexpected (message sanitised) |

## 4. Infrastructure context

### Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `HRIS_DB_URI` | prod | mock URI | PostgreSQL/Workday connection (credentials never logged) |
| `SMTP_RELAY` | prod | `smtp-relay.acme-corp.example:587` | Enterprise relay for payslips |
| `LLM_API_KEY` | optional | – | Enables LLM intent parsing (and the LLM judge) via litellm |
| `LLM_MODEL` | optional | `gpt-4o-mini` | litellm model id |
| `OLLAMA_HOST` | optional | – | Local/private model endpoint, e.g. `http://ollama:11434` |
| `PAYROLL_USE_LLM` | optional | `1` | Set `0` to force deterministic rule parsing |
| `LOG_LEVEL` | optional | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` |
| `PAYROLL_HITL_THRESHOLD` | optional | `10000` | USD variance that forces human review |
| `ALLOWED_EMAIL_DOMAINS` | optional | `acme-corp.example` | Payslip / recipient allow-list |
| `PAY_PERIOD_START` | optional | `2026-10-26` | Monday of the active period |
| `MCP_FORCE_ROLE` | optional | – | Pin caller role for a deployment |
| `MCP_HOST` / `MCP_PORT` | optional | `127.0.0.1` / `8000` | SSE / HTTP bind |
| `HRIS_SIMULATE_FLAKY` | dev | `1` | Mock HRIS fails once for EMP071 to exercise retries |

### Logging
Structured JSON (structlog when installed, stdlib fallback otherwise) on stderr with ISO timestamps. A
redaction processor scrubs SSN patterns, e-mail local parts and sensitive keys from **every** event.

### State and persistence
`build_graph()` compiles with `MemorySaver` (in-process). For multi-replica or restart-safe HITL swap in a
durable saver (e.g. `langgraph-checkpoint-postgres`'s `AsyncPostgresSaver`) and use sticky routing or a shared
store so `resume_human_review` can find the thread. The DLQ and the HRIS/SMTP/PDF back ends are mocks.

### Deployment topologies

| Topology | Transport | Notes |
|---|---|---|
| Local / desktop agent | stdio | One process per client; no network exposure |
| Containerised service | SSE or streamable-HTTP | Terminate TLS + authN at the gateway; set `MCP_FORCE_ROLE` or propagate identity |
| Kubernetes | SSE behind an ingress | Durable checkpointer, `readOnlyRootFilesystem`, network policy to HRIS/SMTP only |

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY scripts ./scripts
COPY reference ./reference
COPY assets ./assets
USER 10001
ENTRYPOINT ["python", "scripts/mcp_server.py", "--transport", "sse", "--host", "0.0.0.0", "--port", "8000"]
```

```yaml
# Kubernetes sketch (trimmed)
apiVersion: apps/v1
kind: Deployment
metadata: { name: payroll-mcp }
spec:
  replicas: 2
  selector: { matchLabels: { app: payroll-mcp } }
  template:
    metadata: { labels: { app: payroll-mcp } }
    spec:
      securityContext: { runAsNonRoot: true, runAsUser: 10001 }
      containers:
        - name: server
          image: registry.acme-corp.example/payroll-mcp:1.0.0
          ports: [{ containerPort: 8000 }]
          env:
            - { name: LOG_LEVEL, value: INFO }
            - { name: MCP_FORCE_ROLE, value: HR_MANAGER }
            - name: HRIS_DB_URI
              valueFrom: { secretKeyRef: { name: hris-ro, key: uri } }
            - name: LLM_API_KEY
              valueFrom: { secretKeyRef: { name: llm, key: key } }
          securityContext: { readOnlyRootFilesystem: true, allowPrivilegeEscalation: false }
          readinessProbe: { tcpSocket: { port: 8000 }, periodSeconds: 10 }
```

## 5. Package layout

```
Skill.md                        this manifest
scripts/tools.py                async tools, Pydantic v2 models, exceptions, compliance table
scripts/orchestrator.py         LangGraph state machine (guardrail → parse → extract → calculate → HITL/deliver)
scripts/mcp_server.py           MCP server (FastMCP) with JSON-RPC error mapping
reference/architecture_spec.md  diagrams, RPA vs. agentic IPA narrative, threat model
reference/compliance_rules.md   mock tax manual used for grounding
assets/email_template.html      Jinja2 payslip template (masked PII, itemised deductions)
evals/                          positive/negative queries, rubrics.json, judges.py (LLM-as-judge)
requirements.txt                dependencies
```

## 6. Quick start

```bash
pip install -r requirements.txt
python scripts/orchestrator.py          # four demo scenarios (clean, HITL, DLQ, injection)
python scripts/mcp_server.py            # stdio MCP server
python evals/judges.py --offline        # evaluation report -> evals/report.md
```
