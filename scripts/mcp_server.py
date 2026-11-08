"""MCP server exposing the payroll LangGraph workflow to enterprise LLM clients.

Tools
-----
``run_payroll``          Start a run from a nested JSON payload (requester, batch, adjustments, notes).
``resume_human_review``  Resume a run that is paused at the HITL node (four-eyes enforced).
``get_run_state``        Read a PII-redacted snapshot of any run from the checkpointer.

Resource
--------
``payroll://compliance/rules``  The mock compliance manual the calculations are grounded in.

Error bubbling
--------------
The Python SDK turns any exception raised inside a tool into an ``isError`` result. To surface
*protocol-level* JSON-RPC error codes instead, tools stash a mapped :class:`ErrorData` in a
context variable and a wrapper around the ``tools/call`` handler re-raises it as
:class:`McpError`:

=====================  ======  ==========================================================
Condition              Code    Meaning
=====================  ======  ==========================================================
validation / no scope  -32602  ``INVALID_PARAMS``
employee not found     -32001  custom: resource not found
HRIS unavailable       -32002  custom: upstream dependency unavailable
access / policy / DLP  -32003  custom: forbidden (guardrail rejection, RBAC, four-eyes)
calculation anomaly    -32004  custom: unprocessable payroll state
anything else          -32603  ``INTERNAL_ERROR``
=====================  ======  ==========================================================

Run: ``python scripts/mcp_server.py --transport stdio`` (default) or ``--transport sse``.
Logs go to stderr; stdout belongs to the stdio transport.
"""

from __future__ import annotations

import argparse
import os
import re
from contextvars import ContextVar
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Optional

from mcp import types
from mcp.server.fastmcp import FastMCP
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

import orchestrator
from tools import (
    AccessDeniedError,
    Adjustment,
    EmployeeNotFoundError,
    HRISUnavailableError,
    PayPeriod,
    PayrollError,
    PolicyViolationError,
    Role,
    TaxCalculationAnomaly,
    default_pay_period,
    get_logger,
    redact_pii,
)

log = get_logger("payroll.mcp")

SERVER_NAME = "payroll-automation"
SERVER_VERSION = "1.0.0"
RULES_PATH = Path(__file__).resolve().parent.parent / "reference" / "compliance_rules.md"

NOT_FOUND = -32001
UPSTREAM_UNAVAILABLE = -32002
FORBIDDEN = -32003
UNPROCESSABLE = -32004

_CODE_BY_ERROR: dict[str, int] = {
    "EMPLOYEE_NOT_FOUND": NOT_FOUND,
    "HRIS_UNAVAILABLE": UPSTREAM_UNAVAILABLE,
    "TAX_CALCULATION_ANOMALY": UNPROCESSABLE,
    "MISSING_CRITICAL_DATA": INVALID_PARAMS,
    "ACCESS_DENIED": FORBIDDEN,
    "POLICY_VIOLATION": FORBIDDEN,
    "ROLE_NOT_PERMITTED": FORBIDDEN,
}
_GUARDRAIL_CODES = {
    "PROMPT_INJECTION", "CONTROL_BYPASS", "SALARY_MUTATION", "DESTRUCTIVE_DATA_OPERATION",
    "FUNDS_MOVEMENT", "PRIVILEGE_ESCALATION", "PII_EXFILTRATION", "DATA_EXFILTRATION",
    "EXTERNAL_RECIPIENT",
}

_PENDING_ERROR: ContextVar[Optional[ErrorData]] = ContextVar("pending_mcp_error", default=None)

mcp = FastMCP(
    SERVER_NAME,
    instructions=(
        "Enterprise payroll automation. Supports multi-state payroll calculation, overtime, "
        "bonuses, garnishments and encrypted payslip delivery with human review for anomalies. "
        "It never moves money, changes compensation data or e-mails outside the corporate domain."
    ),
    host=os.getenv("MCP_HOST", "127.0.0.1"),
    port=int(os.getenv("MCP_PORT", "8000")),
    log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
)

# --------------------------------------------------------------------------------------
# Nested request schemas
# --------------------------------------------------------------------------------------


class Requester(BaseModel):
    """Caller identity. In production bind this to the authenticated principal."""

    model_config = ConfigDict(extra="forbid")

    requester_id: str = Field(min_length=1, max_length=128)
    role: Role = Role.PAYROLL_ADMIN


class BatchScope(BaseModel):
    """Which employees to process (explicit ids and/or a department/state filter)."""

    model_config = ConfigDict(extra="forbid")

    emp_ids: list[str] = Field(default_factory=list, max_length=500)
    department: Optional[str] = Field(default=None, max_length=64)
    state: Optional[str] = Field(default=None, pattern=r"^(CA|TX|NY)$")

    @field_validator("emp_ids")
    @classmethod
    def _ids_shape(cls, value: list[str]) -> list[str]:
        """Reject anything that is not a strict ``EMP###`` token (blocks SQL/command payloads)."""
        cleaned = [v.strip().upper() for v in value]
        if any(not re.fullmatch(r"EMP\d{3,6}", v) for v in cleaned):
            raise ValueError("emp_ids must match ^EMP[0-9]{3,6}$")
        return cleaned


class RunOptions(BaseModel):
    """Optional execution controls."""

    model_config = ConfigDict(extra="forbid")

    thread_id: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{4,64}$")
    period_start: Optional[date] = Field(default=None, description="Monday of the pay period")


class RunPayrollRequest(BaseModel):
    """Complex nested payload accepted from external orchestrators."""

    model_config = ConfigDict(extra="forbid")

    requester: Requester
    batch: BatchScope = Field(default_factory=BatchScope)
    adjustments: list[Adjustment] = Field(default_factory=list, max_length=500)
    notes: str = Field(default="", max_length=2000, description="Free text; guardrail-screened")
    options: RunOptions = Field(default_factory=RunOptions)


# --------------------------------------------------------------------------------------
# Error mapping
# --------------------------------------------------------------------------------------


def to_error_data(exc: BaseException) -> ErrorData:
    """Map any exception raised by the skill to a standard MCP/JSON-RPC error."""
    if isinstance(exc, ValidationError):
        details = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()][:10]
        return ErrorData(code=INVALID_PARAMS, message="Invalid request payload",
                         data={"errors": redact_pii(details)})
    if isinstance(exc, EmployeeNotFoundError):
        return ErrorData(code=NOT_FOUND, message=str(exc), data={"emp_ids": exc.emp_ids})
    if isinstance(exc, HRISUnavailableError):
        return ErrorData(code=UPSTREAM_UNAVAILABLE, message=str(exc), data={"retryable": True})
    if isinstance(exc, (AccessDeniedError, PolicyViolationError)):
        return ErrorData(code=FORBIDDEN, message=str(exc), data={"error": exc.code})
    if isinstance(exc, TaxCalculationAnomaly):
        return ErrorData(code=UNPROCESSABLE, message=str(exc), data={"error": exc.code})
    if isinstance(exc, PayrollError):
        return ErrorData(code=INTERNAL_ERROR, message=str(exc), data={"error": exc.code})
    log.error("unhandled_tool_exception", error_type=type(exc).__name__)
    return ErrorData(code=INTERNAL_ERROR, message="Internal error while executing payroll workflow")


def _raise_mapped(exc: BaseException) -> None:
    """Record the mapped error for the protocol-level wrapper, then raise it as ``McpError``."""
    err = to_error_data(exc)
    _PENDING_ERROR.set(err)
    raise McpError(err) from exc


def _outcome_error(snapshot: dict[str, Any]) -> Optional[ErrorData]:
    """Translate a terminal graph state (rejected / denied / dead-lettered) into an error."""
    status = snapshot.get("status")
    if status not in {"rejected", "access_denied", "dead_lettered"}:
        return None
    errors = snapshot.get("errors", [])
    codes = [e["code"] for e in errors]
    if status in {"rejected", "access_denied"} or any(c in _GUARDRAIL_CODES for c in codes):
        code = FORBIDDEN
    else:
        code = next((_CODE_BY_ERROR[c] for c in codes if c in _CODE_BY_ERROR), INTERNAL_ERROR)
    return ErrorData(
        code=code, message=f"Payroll run ended in terminal state '{status}'",
        data={"thread_id": snapshot.get("thread_id"), "status": status, "errors": errors,
              "dead_letter_id": snapshot.get("dead_letter_id")},
    )


def _install_protocol_error_bridge() -> None:
    """Wrap ``tools/call`` so mapped errors surface as JSON-RPC errors (not ``isError`` results)."""
    handlers = mcp._mcp_server.request_handlers  # noqa: SLF001 - SDK has no public hook
    original = handlers[types.CallToolRequest]

    async def bridged(req: types.CallToolRequest) -> Any:
        _PENDING_ERROR.set(None)
        result = await original(req)
        pending = _PENDING_ERROR.get()
        if pending is not None:
            _PENDING_ERROR.set(None)
            raise McpError(pending)
        inner = getattr(result, "root", result)
        if getattr(inner, "isError", False):
            text = " ".join(getattr(c, "text", "") for c in inner.content)
            if "validation error" in text.lower():  # SDK-level argument validation
                lines = [ln.strip() for ln in text.splitlines()][1:4]
                raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid request payload",
                                         data={"errors": redact_pii(lines)}))
        return result

    handlers[types.CallToolRequest] = bridged


# --------------------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------------------


def _effective_role(claimed: Role) -> Role:
    """Honour ``MCP_FORCE_ROLE`` so a deployment can pin identity regardless of payload claims."""
    forced = os.getenv("MCP_FORCE_ROLE")
    if forced:
        return Role(forced)
    return claimed


@mcp.tool()
async def run_payroll(request: RunPayrollRequest) -> dict[str, Any]:
    """Run payroll for a batch. Returns a redacted run snapshot.

    If the run needs human review the snapshot has ``paused_for_review=true`` and an
    ``interrupt`` payload; call ``resume_human_review`` with the returned ``thread_id``.
    Guardrail rejections, access denials and dead-lettered batches raise protocol errors.
    """
    try:
        period: Optional[PayPeriod] = None
        if request.options.period_start:
            start = request.options.period_start
            period = PayPeriod(start=start, end=start + timedelta(days=13),
                               pay_date=start + timedelta(days=18))
        role = _effective_role(request.requester.role)
        snapshot = await orchestrator.run_payroll(
            request.notes, role=role.value, requester_id=request.requester.requester_id,
            thread_id=request.options.thread_id, emp_ids=request.batch.emp_ids,
            department=request.batch.department, state_filter=request.batch.state,
            adjustments=[a.model_dump(mode="json") for a in request.adjustments],
            period=period or default_pay_period())
        error = _outcome_error(snapshot)
        if error is not None:
            _PENDING_ERROR.set(error)
            raise McpError(error)
        return snapshot
    except McpError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalised below
        _raise_mapped(exc)
        raise  # pragma: no cover


@mcp.tool()
async def resume_human_review(thread_id: str, approved: bool, reviewer: str,
                              note: str = "") -> dict[str, Any]:
    """Resume a run paused for human review. ``reviewer`` must differ from the requester."""
    try:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{4,64}", thread_id):
            raise PolicyViolationError("malformed thread_id")
        snapshot = await orchestrator.resume_review(thread_id, approved=approved, reviewer=reviewer,
                                                    note=note)
        error = _outcome_error(snapshot)
        if error is not None:
            _PENDING_ERROR.set(error)
            raise McpError(error)
        return snapshot
    except McpError:
        raise
    except Exception as exc:  # noqa: BLE001
        _raise_mapped(exc)
        raise  # pragma: no cover


@mcp.tool()
async def get_run_state(thread_id: str, role: Role = Role.AUDITOR) -> dict[str, Any]:
    """Return a PII-redacted snapshot of a run (PAYROLL_ADMIN, HR_MANAGER or AUDITOR only)."""
    try:
        if _effective_role(role) not in {Role.PAYROLL_ADMIN, Role.HR_MANAGER, Role.AUDITOR}:
            raise AccessDeniedError("role may not read run state")
        snapshot = await orchestrator.get_run_snapshot(thread_id)
        if not snapshot.get("found"):
            raise EmployeeNotFoundError([thread_id])
        return snapshot
    except McpError:
        raise
    except Exception as exc:  # noqa: BLE001
        _raise_mapped(exc)
        raise  # pragma: no cover


@mcp.resource("payroll://compliance/rules", mime_type="text/markdown")
def compliance_rules() -> str:
    """The FY2026 mock compliance manual used to ground every calculation."""
    return RULES_PATH.read_text(encoding="utf-8")


_install_protocol_error_bridge()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Payroll automation MCP server")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="stdio")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()
    if args.host:
        mcp.settings.host = args.host
    if args.port:
        mcp.settings.port = args.port
    log.info("mcp_server_starting", transport=args.transport, version=SERVER_VERSION)
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
