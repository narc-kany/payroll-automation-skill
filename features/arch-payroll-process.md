# Plan: Enterprise Payroll Process Automation — AI Skill Package

## Context
The user wants a production-style AI Skill package for payroll automation, built from scratch. It uses LangGraph orchestration with checkpointing and human-in-the-loop (HITL) review, Pydantic v2 contracts, async tools, an MCP server bridge, compliance reference docs, an HTML payslip template and an LLM-as-judge eval harness. The workspace `C:\Users\user\Documents\payroll_automation_skill` is empty, and its name already matches the blueprint's root folder, so **files are written straight into this directory** rather than into a nested `payroll_automation_skill/` folder.

Environment: Python 3.11.9, langgraph 1.0.5, langgraph-checkpoint 3.0.1, langchain-core 1.6.2, mcp 1.12.3, pydantic 2.11.7, litellm 1.72.0 are installed. **structlog is missing.** Add a `requirements.txt` that includes it, and fall back to stdlib JSON logging when structlog cannot be imported.

## Design decisions
- **Deterministic math, LLM optional.** Tax and pay math uses `decimal.Decimal` with ROUND_HALF_UP. Rates come from one in-code `COMPLIANCE_TABLE` that mirrors `reference/compliance_rules.md` exactly, so the judge can check grounding. An LLM, called through litellm with `LLM_API_KEY` or `OLLAMA_HOST`, is used only for intent parsing. A rule-based regex fallback lets the graph run offline.
- **Mock backends.** The HRIS is an in-memory async repo with about 10 employees across CA, TX and NY (EMP001, EMP007, EMP019, EMP042, a CEO record and others). It simulates latency and transient failures, retried with exponential backoff and no extra dependency. SMTP and PDF are simulated: encryption is mocked with `hashlib` and `secrets`, and nothing is actually sent.
- **The tax rules are mock data, labeled "FY2026 MOCK — not tax advice."** They cover:
  - federal brackets
  - FICA and the Social Security wage base
  - California daily overtime (over 8h/day at 1.5x, over 12h at 2x), against Texas FLSA weekly-only overtime
  - New York state brackets
  - the 401(k) limit
  - the bonus supplemental withholding split: 22%, or 37% above $1M
  - CCPA-style garnishment limits: 25% of disposable pay or 30x the minimum wage
  - the order in which pre-tax deductions apply

## Files
1. **`Skill.md`**
   - Frontmatter: name, version 1.0.0 (semver), author, description.
   - SLAs: p95 latency, availability, RPO/RTO.
   - Capabilities and anti-goals: no bank transfers, no salary changes, no email to external domains, no DDL/DML.
   - MCP config: stdio and SSE transports, protocol `2025-06-18`, JSON-RPC tool schemas.
   - Environment variables: `HRIS_DB_URI`, `SMTP_RELAY`, `LLM_API_KEY`, `LLM_MODEL`, `OLLAMA_HOST`, `LOG_LEVEL`, `PAYROLL_HITL_THRESHOLD`, `ALLOWED_EMAIL_DOMAINS`.
   - A Docker/K8s deployment sketch.
2. **`scripts/tools.py`**
   - Exceptions: a `PayrollError` base class with `EmployeeNotFoundError`, `HRISUnavailableError`, `TaxCalculationAnomaly`, `AccessDeniedError` and `PolicyViolationError`.
   - Models:
     - `Role` enum and `RequestContext` for role-based access
     - `EmployeeRecord`, with the SSN as `SecretStr` and a `masked_ssn` property
     - `TimesheetEntry`, with daily hours constrained to 0–24
     - `DeductionElections` and `PayrollInput`
     - `TaxBreakdown`
     - `PayrollResult`, whose `@model_validator` enforces net ≤ gross, net ≥ 0, and that the components sum to the totals
     - `PayslipDeliveryReceipt`
   - PII helpers: `mask_ssn`, `mask_email`, `mask_account`, `redact_pii(dict)`.
   - Async core functions with `@tool(args_schema=...)` wrappers from `langchain_core.tools`: `extract_hris_data`, `calculate_payroll_taxes`, `deliver_secure_payslip`. Delivery checks the recipient's domain against an allowlist and renders `assets/email_template.html` with Jinja2, falling back to `string.Template`.
3. **`scripts/orchestrator.py`**
   - `PayrollState(TypedDict)` with: `request_id`, `query`, `emp_ids`, `emp_id`, `adjustments`, `audit_trail` (an Annotated list with an add reducer), `financial_context`, `status`, `confidence_score`, `error_stack`, `results`, `requester_role`.
   - Nodes:
     - `guardrail_node`: rejects prompt injection, scope creep, SQL/DDL and data-exfiltration patterns
     - `intent_parser_node`: uses the LLM or the rules to pull out employee IDs, bonus %, 401(k) max and proration
     - `extract_node`
     - `calculate_node`: computes the confidence score and flags a discrepancy over $10,000 against the prior period
     - `human_review_node`: pauses with `langgraph.types.interrupt` and resumes with `Command(resume=...)`
     - `deliver_node`, `dead_letter_queue_node`, `finalize_node`
   - Routing:
     - guardrail → reject, or go on to parsing
     - extract → dead-letter queue if critical data is missing
     - calculate → human review if confidence is below 0.85 or a discrepancy is found, otherwise delivery
   - Entry points: `build_graph(checkpointer=MemorySaver())`, async `run_payroll(query, role, thread_id)` and `resume_review(thread_id, decision)`, plus a `__main__` demo.
4. **`scripts/mcp_server.py`**
   - `FastMCP("payroll-automation")` with these tools:
     - `run_payroll`, which takes a nested Pydantic payload (requester, batch, adjustments, options)
     - `resume_human_review`
     - `get_run_state`, which reads the checkpointer and redacts PII
   - A `compliance_rules` resource.
   - Errors map to `McpError(ErrorData(code=...))`:

     | Error | Code |
     |---|---|
     | Validation | INVALID_PARAMS (-32602) |
     | Not found | -32001 (custom) |
     | Access denied or policy violation | -32003 |
     | Anything else | INTERNAL_ERROR (-32603) |

   - A `--transport stdio|sse` CLI flag.
5. **`reference/architecture_spec.md`**
   - A Mermaid flowchart: MCP client → server → graph nodes → tools → mock HRIS/SMTP, with the HITL and dead-letter branches.
   - A sequence diagram.
   - A narrative contrasting RPA with agentic IPA, a threat model and the checkpointing design.
6. **`reference/compliance_rules.md`** — the numbered mock tax manual. Sections are cited as `§x.y` so the judge can check grounding.
7. **`assets/email_template.html`** — a responsive Jinja2 template using tables and inline CSS. It has brand placeholders, a masked SSN and account number, `{% for %}` loops for earnings and pre-tax and post-tax deductions, year-to-date totals and a confidentiality footer.
8. **`evals/positive.txt` and `evals/negative.txt`** — 5 queries each, one per line.
   - Positive: the spec's example, plus multi-state overtime, garnishment and supplemental-bonus cases.
   - Negative: prompt injection, salary changes, DDL, exfiltration to an external address, role escalation.
9. **`evals/rubrics.json`** — four dimensions: schema_adherence, compliance_grounding, boundary_defense, resilience. Each has a weight, a 1–5 scale with anchors, whether it applies to positive or negative queries, and a pass threshold.
10. **`evals/judges.py`** — an async script that:
    - loads the queries
    - calls `run_payroll` natively, auto-approves HITL interrupts on a separate resume pass and records them
    - redacts the final state
    - asks a litellm judge for JSON scores (`--judge-model`); `--offline` uses a deterministic heuristic judge instead
    - limits concurrency with `asyncio.Semaphore`
    - writes a Markdown report to `evals/report.md` and stdout
11. **`requirements.txt`** — langgraph, langchain-core, mcp, pydantic, structlog, litellm, jinja2.

## Verification
1. `pip install -r requirements.txt`
2. `python -m py_compile scripts/*.py evals/judges.py`
3. `python scripts/orchestrator.py`. The demo runs four cases: a clean run, a run that hits the HITL interrupt and is then resumed, a dead-letter run (unknown employee) and a rejected injection.
4. `python evals/judges.py --offline` produces the report, and the negative queries score high on boundary_defense.
5. MCP smoke test: a short in-process client using `mcp.client.stdio` lists the tools and calls `run_payroll`.
