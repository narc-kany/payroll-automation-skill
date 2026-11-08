"""Enterprise payroll tools: HRIS extraction, tax computation and secure payslip delivery.

This module is the *only* place that touches (mock) systems of record. Everything that
crosses an agent boundary is a validated Pydantic v2 model and is PII-minimised:

* raw SSNs and bank accounts live only inside :class:`EmployeeRecord` (``SecretStr``) and
  never leave :class:`MockHRISClient`; downstream code sees :class:`EmployeeProfile`
  carrying masked values only;
* all monetary math uses :class:`decimal.Decimal` with ``ROUND_HALF_UP`` and mirrors
  ``reference/compliance_rules.md`` section by section (see :data:`COMPLIANCE`);
* every I/O bound operation is ``async`` and instrumented with structured JSON logs
  written to **stderr** (stdout is reserved for the MCP stdio transport).

All rates are FY2026 *mock* values and are not tax advice.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import sys
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Awaitable, Callable, Literal, Optional, Sequence, TypeVar

from langchain_core.tools import tool
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    model_validator,
)

__all__ = [
    "COMPLIANCE",
    "AccessDeniedError",
    "Adjustment",
    "EmployeeNotFoundError",
    "EmployeeProfile",
    "HRISUnavailableError",
    "PayPeriod",
    "PayrollError",
    "PayrollInput",
    "PayrollResult",
    "PayslipDeliveryError",
    "PayslipDeliveryReceipt",
    "PolicyViolationError",
    "RequestContext",
    "Role",
    "TaxCalculationAnomaly",
    "calculate_payroll_taxes",
    "default_pay_period",
    "deliver_secure_payslip",
    "extract_hris_data",
    "get_logger",
    "mask_account",
    "mask_email",
    "mask_ssn",
    "redact_pii",
]

T = TypeVar("T")

# --------------------------------------------------------------------------------------
# Structured logging (structlog when available, JSON-over-stdlib otherwise)
# --------------------------------------------------------------------------------------

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-(\d{4})\b")
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(ssn|password|secret|api_key|token|routing)(_|$)|bank_account|account_number"
    r"|social_security_number|^account$",
    re.I,
)


def mask_ssn(value: str) -> str:
    """Return ``XXX-XX-1234`` for any SSN-like input (digits only are inspected)."""
    digits = re.sub(r"\D", "", str(value))
    return f"XXX-XX-{digits[-4:].rjust(4, 'X')}"


def mask_account(value: str) -> str:
    """Return ``****1234`` for a bank account number."""
    digits = re.sub(r"\D", "", str(value))
    return f"****{digits[-4:].rjust(4, 'X')}"


def mask_email(value: str) -> str:
    """Return ``j***@domain`` for an e-mail address."""
    return _EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", str(value))


def redact_pii(obj: Any) -> Any:
    """Recursively redact PII from dicts, lists and strings.

    Keys that look sensitive are replaced wholesale; free-text values have SSNs and e-mail
    local parts masked. ``SecretStr`` instances are never revealed.
    """
    if isinstance(obj, SecretStr):
        return "**REDACTED**"
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, val in obj.items():
            if _SENSITIVE_KEY_RE.search(str(key)) and not str(key).startswith("masked_"):
                out[key] = "**REDACTED**"
            else:
                out[key] = redact_pii(val)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact_pii(v) for v in obj]
    if isinstance(obj, str):
        return mask_email(_SSN_RE.sub(lambda m: f"XXX-XX-{m.group(1)}", obj))
    return obj


def _log_level() -> int:
    level = logging.getLevelName(os.getenv("LOG_LEVEL", "INFO").upper())
    return level if isinstance(level, int) else logging.INFO


class _JsonLogger:
    """Minimal structlog-compatible JSON logger used when structlog is not installed."""

    _configured = False

    def __init__(self, name: str, ctx: Optional[dict[str, Any]] = None) -> None:
        self._name = name
        self._ctx: dict[str, Any] = dict(ctx or {})
        self._log = logging.getLogger("payroll")
        if not _JsonLogger._configured:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._log.addHandler(handler)
            self._log.propagate = False
            _JsonLogger._configured = True
        self._log.setLevel(_log_level())

    def bind(self, **kwargs: Any) -> "_JsonLogger":
        """Return a child logger with additional bound context."""
        return _JsonLogger(self._name, {**self._ctx, **kwargs})

    def _emit(self, level: int, event: str, **kwargs: Any) -> None:
        if not self._log.isEnabledFor(level):
            return
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": logging.getLevelName(level).lower(),
            "logger": self._name,
            "event": event,
            **self._ctx,
            **kwargs,
        }
        self._log.log(level, json.dumps(redact_pii(record), default=str))

    def debug(self, event: str, **kw: Any) -> None:
        """Emit a DEBUG event."""
        self._emit(logging.DEBUG, event, **kw)

    def info(self, event: str, **kw: Any) -> None:
        """Emit an INFO event."""
        self._emit(logging.INFO, event, **kw)

    def warning(self, event: str, **kw: Any) -> None:
        """Emit a WARNING event."""
        self._emit(logging.WARNING, event, **kw)

    def error(self, event: str, **kw: Any) -> None:
        """Emit an ERROR event."""
        self._emit(logging.ERROR, event, **kw)


def _structlog_redactor(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor that scrubs PII from every event."""
    return redact_pii(event_dict)


def get_logger(name: str) -> Any:
    """Return a structured JSON logger (structlog if installed, stdlib fallback otherwise)."""
    try:
        import structlog  # type: ignore[import-not-found]

        if not getattr(get_logger, "_structlog_ready", False):
            structlog.configure(
                processors=[
                    structlog.contextvars.merge_contextvars,
                    structlog.processors.add_log_level,
                    structlog.processors.TimeStamper(fmt="iso", utc=True),
                    _structlog_redactor,
                    structlog.processors.JSONRenderer(default=str),
                ],
                wrapper_class=structlog.make_filtering_bound_logger(_log_level()),
                logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
                cache_logger_on_first_use=True,
            )
            get_logger._structlog_ready = True  # type: ignore[attr-defined]
        return structlog.get_logger(name)
    except ImportError:
        return _JsonLogger(name)


log = get_logger("payroll.tools")

# --------------------------------------------------------------------------------------
# Custom exceptions
# --------------------------------------------------------------------------------------


class PayrollError(Exception):
    """Base class for every domain error raised by the payroll skill."""

    code = "PAYROLL_ERROR"


class EmployeeNotFoundError(PayrollError):
    """One or more requested employees do not exist in the HRIS."""

    code = "EMPLOYEE_NOT_FOUND"

    def __init__(self, emp_ids: Sequence[str]) -> None:
        self.emp_ids = list(emp_ids)
        super().__init__(f"Employee(s) not found in HRIS: {', '.join(self.emp_ids)}")


class HRISUnavailableError(PayrollError):
    """The HRIS could not be reached (transient, retried) or retries were exhausted."""

    code = "HRIS_UNAVAILABLE"


class TaxCalculationAnomaly(PayrollError):
    """A calculation produced an impossible or policy-violating state (e.g. net > gross)."""

    code = "TAX_CALCULATION_ANOMALY"


class AccessDeniedError(PayrollError):
    """The caller's role does not permit the requested operation."""

    code = "ACCESS_DENIED"


class PolicyViolationError(PayrollError):
    """The request violates a hard compliance policy (e.g. external e-mail recipient)."""

    code = "POLICY_VIOLATION"


class PayslipDeliveryError(PayrollError):
    """Payslip generation or SMTP dispatch failed."""

    code = "PAYSLIP_DELIVERY_FAILED"


# --------------------------------------------------------------------------------------
# Compliance table (mirrors reference/compliance_rules.md)
# --------------------------------------------------------------------------------------

Bracket = tuple[Optional[Decimal], Decimal]
CENT = Decimal("0.01")
ZERO = Decimal("0")


def D(value: Any) -> Decimal:  # noqa: N802 - short constructor, intentional
    """Build a ``Decimal`` from any value via ``str`` (never from a binary float)."""
    return Decimal(str(value))


def q(value: Any) -> Decimal:
    """Quantise to cents using half-up rounding (compliance §1.2)."""
    return D(value).quantize(CENT, rounding=ROUND_HALF_UP)


def _brackets(*pairs: tuple[Optional[str], str]) -> tuple[Bracket, ...]:
    return tuple((None if upper is None else D(upper), D(rate)) for upper, rate in pairs)


@dataclass(frozen=True)
class StateRule:
    """State-level withholding parameters (compliance §6, §7.3)."""

    brackets: tuple[Bracket, ...]
    standard_deduction: Decimal
    supplemental_rate: Decimal
    sdi_rate: Decimal
    sdi_cap: Optional[Decimal]
    sections: tuple[str, ...]


@dataclass(frozen=True)
class ComplianceTable:
    """Immutable view of the FY2026 mock tax manual."""

    periods_per_year: int = 26
    working_days_per_period: int = 10
    federal_brackets: tuple[Bracket, ...] = _brackets(
        ("11925", "0.10"), ("48475", "0.12"), ("103350", "0.22"), ("197300", "0.24"),
        ("250525", "0.32"), ("626350", "0.35"), (None, "0.37"),
    )
    federal_std_deduction: Decimal = D("15000")
    ss_rate: Decimal = D("0.062")
    ss_wage_base: Decimal = D("184500")
    medicare_rate: Decimal = D("0.0145")
    addl_medicare_rate: Decimal = D("0.009")
    addl_medicare_threshold: Decimal = D("200000")
    k401_annual_limit: Decimal = D("24500")
    supplemental_flat_rate: Decimal = D("0.22")
    supplemental_high_rate: Decimal = D("0.37")
    supplemental_threshold: Decimal = D("1000000")
    max_bonus: Decimal = D("5000000")
    max_bonus_pct: Decimal = D("100")
    overtime_multiplier: Decimal = D("1.5")
    double_time_multiplier: Decimal = D("2.0")
    ca_daily_regular: Decimal = D("8")
    ca_daily_double: Decimal = D("12")
    weekly_overtime_threshold: Decimal = D("40")
    garnish_creditor_pct: Decimal = D("0.25")
    garnish_support_pct: Decimal = D("0.50")
    garnish_combined_pct: Decimal = D("0.50")
    federal_min_wage: Decimal = D("7.25")
    garnish_floor_weekly_multiple: Decimal = D("30")
    min_tax_rate: Decimal = D("0.05")
    max_tax_rate: Decimal = D("0.55")
    hitl_confidence_threshold: float = 0.85


COMPLIANCE = ComplianceTable()

STATE_RULES: dict[str, StateRule] = {
    "TX": StateRule((), ZERO, ZERO, ZERO, None, ("§6.1", "§7.3")),
    "CA": StateRule(
        _brackets(("10756", "0.01"), ("25499", "0.02"), ("40245", "0.04"), ("55866", "0.06"),
                  ("70606", "0.08"), ("360659", "0.093"), (None, "0.123")),
        D("5540"), D("0.1023"), D("0.012"), None, ("§6.2", "§6.3", "§7.3"),
    ),
    "NY": StateRule(
        _brackets(("8500", "0.04"), ("11700", "0.045"), ("13900", "0.0525"), ("80650", "0.055"),
                  ("215400", "0.06"), (None, "0.0685")),
        D("8000"), D("0.117"), D("0.005"), D("1.20"), ("§6.4", "§6.5", "§7.3"),
    ),
}

STATE_NAMES = {"CALIFORNIA": "CA", "TEXAS": "TX", "NEW YORK": "NY"}

# --------------------------------------------------------------------------------------
# Domain models
# --------------------------------------------------------------------------------------

Money = Annotated[Decimal, Field(ge=0, max_digits=14, decimal_places=2)]
SignedMoney = Annotated[Decimal, Field(max_digits=14, decimal_places=2)]
Hours = Annotated[Decimal, Field(ge=0, max_digits=8, decimal_places=2)]
EmpId = Annotated[str, Field(pattern=r"^EMP\d{3,6}$")]
StateCode = Literal["CA", "TX", "NY"]


class Role(str, Enum):
    """Caller roles for role-based access control (zero-trust: deny by default)."""

    PAYROLL_ADMIN = "PAYROLL_ADMIN"
    HR_MANAGER = "HR_MANAGER"
    AUDITOR = "AUDITOR"
    EMPLOYEE = "EMPLOYEE"


RUN_ROLES = frozenset({Role.PAYROLL_ADMIN, Role.HR_MANAGER})


class RequestContext(BaseModel):
    """Authenticated caller identity propagated into every tool call."""

    model_config = ConfigDict(frozen=True)

    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex, min_length=8, max_length=64)
    requester_id: str = Field(min_length=1, max_length=128)
    role: Role


class PayPeriod(BaseModel):
    """A biweekly Monday–Sunday pay period (compliance §1.1)."""

    model_config = ConfigDict(frozen=True)

    start: date
    end: date
    pay_date: date

    @model_validator(mode="after")
    def _validate_shape(self) -> "PayPeriod":
        if self.start.weekday() != 0:
            raise ValueError("pay period must start on a Monday")
        if (self.end - self.start).days != 13:
            raise ValueError("pay period must span exactly 14 days (biweekly)")
        if self.pay_date <= self.end:
            raise ValueError("pay_date must be after the period end")
        return self

    def working_days(self, from_date: Optional[date] = None) -> int:
        """Count Mon–Fri days from ``from_date`` (default: period start) through period end."""
        cursor = max(from_date or self.start, self.start)
        count = 0
        while cursor <= self.end:
            if cursor.weekday() < 5:
                count += 1
            cursor += timedelta(days=1)
        return count


def default_pay_period() -> PayPeriod:
    """Return the active pay period (``PAY_PERIOD_START`` env, default 2026-10-26)."""
    start = date.fromisoformat(os.getenv("PAY_PERIOD_START", "2026-10-26"))
    end = start + timedelta(days=13)
    return PayPeriod(start=start, end=end, pay_date=end + timedelta(days=5))


class TimesheetEntry(BaseModel):
    """Hours worked on one calendar day."""

    work_date: date
    hours: Hours

    @model_validator(mode="after")
    def _validate_hours(self) -> "TimesheetEntry":
        if self.hours > 24:
            raise ValueError("hours_worked cannot exceed 24 in a single day")
        return self


class Garnishment(BaseModel):
    """A court-ordered garnishment (compliance §8)."""

    kind: Literal["creditor", "child_support"]
    case_ref: str = Field(min_length=3, max_length=32)
    amount: Money = Field(gt=0)


class YTDTotals(BaseModel):
    """Year-to-date totals used for wage-base, threshold and limit logic."""

    gross: Money = ZERO
    ss_wages: Money = ZERO
    k401: Money = ZERO
    supplemental: Money = ZERO


class DeductionElections(BaseModel):
    """Employee benefit elections (read-only for this skill, compliance §9.5)."""

    pct_401k: Annotated[Decimal, Field(ge=0, le=100, decimal_places=2)] = ZERO
    health_premium: Money = ZERO


class _EmployeeBase(BaseModel):
    emp_id: EmpId
    full_name: str = Field(min_length=1, max_length=120)
    work_email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    department: str
    state: StateCode
    pay_type: Literal["salaried", "hourly"]
    annual_salary: Optional[Money] = None
    hourly_rate: Optional[Money] = None
    hire_date: date
    is_executive: bool = False
    elections: DeductionElections = Field(default_factory=DeductionElections)
    garnishments: list[Garnishment] = Field(default_factory=list)
    ytd: YTDTotals = Field(default_factory=YTDTotals)
    prior_period_gross: Money = ZERO
    timesheet: list[TimesheetEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_pay_basis(self) -> "_EmployeeBase":
        if self.pay_type == "salaried" and not self.annual_salary:
            raise ValueError("salaried employees require a positive annual_salary")
        if self.pay_type == "hourly" and not self.hourly_rate:
            raise ValueError("hourly employees require a positive hourly_rate")
        return self


class EmployeeRecord(_EmployeeBase):
    """Raw HRIS record. Holds secrets; confined to :class:`MockHRISClient`."""

    ssn: SecretStr
    bank_account: SecretStr

    def to_profile(self) -> "EmployeeProfile":
        """Project into a data-minimised profile (masked identifiers only)."""
        base = self.model_dump(exclude={"ssn", "bank_account"})
        return EmployeeProfile(
            **base,
            masked_ssn=mask_ssn(self.ssn.get_secret_value()),
            masked_account=mask_account(self.bank_account.get_secret_value()),
        )


class EmployeeProfile(_EmployeeBase):
    """PII-minimised employee view that is safe to place in graph state and logs."""

    masked_ssn: str = Field(pattern=r"^XXX-XX-[0-9X]{4}$")
    masked_account: str = Field(pattern=r"^\*{4}[0-9X]{4}$")


class Adjustment(BaseModel):
    """A structured, whitelisted payroll adjustment (the only mutations ever accepted)."""

    emp_id: EmpId
    kind: Literal["bonus_pct", "bonus_amount", "max_401k", "prorate"]
    value: Optional[Annotated[Decimal, Field(gt=0, decimal_places=2)]] = None
    effective_date: Optional[date] = None
    reason: str = Field(default="", max_length=200)

    @model_validator(mode="after")
    def _validate_kind(self) -> "Adjustment":
        if self.kind == "bonus_pct":
            if self.value is None or self.value > COMPLIANCE.max_bonus_pct:
                raise ValueError("bonus_pct requires 0 < value <= 100 (§7.6)")
        elif self.kind == "bonus_amount":
            if self.value is None or self.value > COMPLIANCE.max_bonus:
                raise ValueError("bonus_amount requires 0 < value <= 5,000,000 (§7.6)")
        elif self.value is not None:
            raise ValueError(f"{self.kind} does not accept a value")
        return self


class PayrollInput(BaseModel):
    """Everything required to compute one employee's payroll for one period."""

    profile: EmployeeProfile
    period: PayPeriod
    adjustments: list[Adjustment] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_consistency(self) -> "PayrollInput":
        emp = self.profile
        if emp.hire_date > self.period.end:
            raise ValueError("employee was hired after the pay period ended")
        for adj in self.adjustments:
            if adj.emp_id != emp.emp_id:
                raise ValueError("adjustment emp_id does not match the employee profile")
        if emp.pay_type == "hourly":
            if not emp.timesheet:
                raise ValueError("hourly employees require timesheet entries")
            for entry in emp.timesheet:
                if not (self.period.start <= entry.work_date <= self.period.end):
                    raise ValueError(f"timesheet date {entry.work_date} is outside the pay period")
        return self


class EarningLine(BaseModel):
    """One earnings line on the payslip."""

    description: str
    hours: Optional[Hours] = None
    rate: Optional[Money] = None
    amount: Money
    ref: str


class TaxBreakdown(BaseModel):
    """Itemised statutory withholdings."""

    federal: Money
    state: Money
    social_security: Money
    medicare: Money
    additional_medicare: Money
    sdi: Money

    @property
    def total(self) -> Decimal:
        """Sum of all statutory withholdings."""
        return q(
            self.federal + self.state + self.social_security + self.medicare
            + self.additional_medicare + self.sdi
        )


class PayrollResult(BaseModel):
    """Validated payroll outcome for one employee (the schema judged by the evals)."""

    emp_id: EmpId
    full_name: str
    masked_ssn: str
    state: StateCode
    period_start: date
    period_end: date
    earnings: list[EarningLine] = Field(min_length=1)
    gross_pay: Money
    k401_deduction: Money
    health_deduction: Money
    taxes: TaxBreakdown
    garnishment: Money
    net_pay: Money
    prior_period_gross: Money
    variance: SignedMoney
    discrepancy: bool
    effective_tax_rate: Annotated[Decimal, Field(ge=0, le=1, decimal_places=4)]
    confidence: Annotated[float, Field(ge=0, le=1)]
    flags: list[str] = Field(default_factory=list)
    compliance_refs: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_money_invariants(self) -> "PayrollResult":
        if self.net_pay > self.gross_pay:
            raise ValueError("impossible state: net_pay exceeds gross_pay")
        earned = q(sum((line.amount for line in self.earnings), ZERO))
        if earned != self.gross_pay:
            raise ValueError(f"earnings lines ({earned}) do not sum to gross_pay ({self.gross_pay})")
        expected = q(
            self.gross_pay - self.k401_deduction - self.health_deduction
            - self.taxes.total - self.garnishment
        )
        if abs(expected - self.net_pay) > CENT:
            raise ValueError(f"net_pay {self.net_pay} does not reconcile with deductions ({expected})")
        return self


class PayslipDeliveryReceipt(BaseModel):
    """Proof of (simulated) encrypted payslip dispatch."""

    message_id: str
    emp_id: EmpId
    recipient_masked: str
    encrypted: bool
    pdf_sha256: str = Field(min_length=64, max_length=64)
    pdf_bytes: int = Field(gt=0)
    smtp_relay: str
    status: Literal["queued", "sent"]
    sent_at: datetime


# --------------------------------------------------------------------------------------
# Resilience helper
# --------------------------------------------------------------------------------------


async def _retry_async(
    op: Callable[[], Awaitable[T]],
    *,
    attempts: int = 4,
    base_delay: float = 0.05,
    retry_on: tuple[type[BaseException], ...] = (HRISUnavailableError,),
    label: str = "operation",
) -> T:
    """Run ``op`` with exponential backoff and jitter; re-raise after the last attempt."""
    for attempt in range(1, attempts + 1):
        try:
            return await op()
        except retry_on as exc:
            if attempt == attempts:
                log.error("retry_exhausted", label=label, attempts=attempts, error=str(exc))
                raise
            delay = base_delay * (2 ** (attempt - 1)) + secrets.randbelow(20) / 1000
            log.warning("retrying", label=label, attempt=attempt, delay_s=round(delay, 3))
            await asyncio.sleep(delay)
    raise HRISUnavailableError(f"{label}: retries exhausted")  # pragma: no cover


# --------------------------------------------------------------------------------------
# Mock HRIS (PostgreSQL / Workday stand-in)
# --------------------------------------------------------------------------------------


def _timesheet(period: PayPeriod, overrides: Optional[dict[date, str]] = None) -> list[TimesheetEntry]:
    """Generate an 8h Mon–Fri timesheet with optional per-day overrides."""
    overrides = overrides or {}
    entries: list[TimesheetEntry] = []
    for offset in range(14):
        day = period.start + timedelta(days=offset)
        if day.weekday() < 5:
            entries.append(TimesheetEntry(work_date=day, hours=D(overrides.get(day, "8"))))
    return entries


def _build_records(period: PayPeriod) -> dict[str, EmployeeRecord]:
    """Build the synthetic employee master data (SSNs are in the invalid 900-series)."""
    week2 = period.start + timedelta(days=7)
    tx_week2 = {week2 + timedelta(days=i): "9" for i in range(5)}  # 45 h in week 2
    ca_long_day = {period.start + timedelta(days=1): "13"}  # Tuesday of week 1

    def salaried(emp_id: str, name: str, email: str, dept: str, state: str, salary: int,
                 ssn: str, acct: str, *, hired: str = "2021-04-12", pct: str = "0",
                 health: str = "0", ytd_k401: str = "0", ytd_supp: str = "0",
                 executive: bool = False, prior: Optional[str] = None,
                 ytd_periods: int = 22, garnishments: Optional[list[Garnishment]] = None,
                 ) -> EmployeeRecord:
        per_period = q(D(salary) / 26)
        ytd_gross = q(per_period * ytd_periods)
        return EmployeeRecord(
            emp_id=emp_id, full_name=name, work_email=f"{email}@acme-corp.example",
            department=dept, state=state, pay_type="salaried", annual_salary=D(salary),
            hire_date=date.fromisoformat(hired), is_executive=executive,
            elections=DeductionElections(pct_401k=D(pct), health_premium=D(health)),
            garnishments=garnishments or [],
            ytd=YTDTotals(gross=ytd_gross, ss_wages=min(ytd_gross, COMPLIANCE.ss_wage_base),
                          k401=D(ytd_k401), supplemental=D(ytd_supp)),
            prior_period_gross=q(prior) if prior is not None else per_period,
            ssn=SecretStr(ssn), bank_account=SecretStr(acct),
        )

    def hourly(emp_id: str, name: str, email: str, dept: str, state: str, rate: str, ssn: str,
               acct: str, ts: list[TimesheetEntry], *, pct: str, health: str,
               prior: str, ytd_gross: str) -> EmployeeRecord:
        return EmployeeRecord(
            emp_id=emp_id, full_name=name, work_email=f"{email}@acme-corp.example",
            department=dept, state=state, pay_type="hourly", hourly_rate=D(rate),
            hire_date=date(2022, 3, 14), timesheet=ts,
            elections=DeductionElections(pct_401k=D(pct), health_premium=D(health)),
            ytd=YTDTotals(gross=D(ytd_gross), ss_wages=D(ytd_gross)),
            prior_period_gross=D(prior), ssn=SecretStr(ssn), bank_account=SecretStr(acct),
        )

    records = [
        salaried("EMP001", "Margaret Chen", "m.chen", "Executive", "NY", 900000,
                 "900-11-0001", "000123450001", pct="0", health="180", ytd_supp="995000",
                 executive=True),
        hourly("EMP003", "Luis Ortega", "l.ortega", "Operations", "TX", "28.50", "900-11-0003",
               "000123450003", _timesheet(period, tx_week2), pct="3", health="85",
               prior="1140.00", ytd_gross="29000.00"),
        hourly("EMP004", "Priya Nair", "p.nair", "Operations", "CA", "41.00", "900-11-0004",
               "000123450004", _timesheet(period, ca_long_day), pct="5", health="120",
               prior="3280.00", ytd_gross="72000.00"),
        salaried("EMP007", "Daniel Okoye", "d.okoye", "Marketing", "NY", 96000, "900-11-0007",
                 "000123450007", hired="2026-11-02", pct="4", health="110", prior="0",
                 ytd_periods=0),
        salaried("EMP019", "Hannah Fischer", "h.fischer", "Marketing", "NY", 128000,
                 "900-11-0019", "000123450019", pct="6", health="150", ytd_k401="19000"),
        salaried("EMP023", "Tomas Brandt", "t.brandt", "Engineering", "CA", 165000,
                 "900-11-0023", "000123450023", pct="5", health="140",
                 garnishments=[Garnishment(kind="child_support", case_ref="CS-2231",
                                           amount=D("600"))]),
        salaried("EMP042", "Sofia Reyes", "s.reyes", "Marketing", "NY", 118000, "900-11-0042",
                 "000123450042", pct="5", health="130"),
        salaried("EMP055", "Marcus Webb", "m.webb", "Marketing", "NY", 84000, "900-11-0055",
                 "000123450055", pct="3", health="100"),
        salaried("EMP060", "Aiko Tanaka", "a.tanaka", "Engineering", "CA", 210000,
                 "900-11-0060", "000123450060", pct="8", health="160", ytd_k401="12000"),
        salaried("EMP071", "Rahul Verma", "r.verma", "Sales", "TX", 90000, "900-11-0071",
                 "000123450071", pct="0", health="90",
                 garnishments=[Garnishment(kind="creditor", case_ref="CR-7710",
                                           amount=D("800"))]),
    ]
    return {r.emp_id: r for r in records}


class MockHRISClient:
    """Async stand-in for a PostgreSQL/Workday HRIS with latency and transient faults.

    ``HRIS_DB_URI`` is read for realism (and logged with credentials stripped). The first
    lookup of ``EMP071`` per process fails once to exercise the retry path; set
    ``HRIS_SIMULATE_FLAKY=0`` to disable.
    """

    def __init__(self, period: Optional[PayPeriod] = None) -> None:
        self._period = period or default_pay_period()
        self._records = _build_records(self._period)
        uri = os.getenv("HRIS_DB_URI", "postgresql://payroll_ro:***@hris.internal:5432/hris")
        self.uri_masked = re.sub(r"//[^@]*@", "//***:***@", uri)
        self._flaky_once = {"EMP071"} if os.getenv("HRIS_SIMULATE_FLAKY", "1") == "1" else set()

    async def fetch(self, emp_id: str) -> EmployeeRecord:
        """Fetch one raw employee record (may raise transient or not-found errors)."""
        await asyncio.sleep(0.005)  # simulated network latency
        if emp_id in self._flaky_once:
            self._flaky_once.discard(emp_id)
            raise HRISUnavailableError(f"transient HRIS timeout for {emp_id}")
        record = self._records.get(emp_id)
        if record is None:
            raise EmployeeNotFoundError([emp_id])
        return record

    async def find_ids(self, department: Optional[str], state: Optional[str]) -> list[str]:
        """Return employee ids matching a department and/or work-state filter."""
        await asyncio.sleep(0.005)
        dept = department.lower() if department else None
        return sorted(
            r.emp_id for r in self._records.values()
            if (dept is None or r.department.lower() == dept)
            and (state is None or r.state == state)
        )

    def executive_ids(self) -> set[str]:
        """Return ids of executive records (restricted to PAYROLL_ADMIN, §9.4)."""
        return {r.emp_id for r in self._records.values() if r.is_executive}

    def departments(self) -> list[str]:
        """Return the known department names (used by the intent parser)."""
        return sorted({r.department for r in self._records.values()})


_hris: Optional[MockHRISClient] = None


def get_hris() -> MockHRISClient:
    """Return the process-wide HRIS client."""
    global _hris
    if _hris is None:
        _hris = MockHRISClient()
    return _hris


# --------------------------------------------------------------------------------------
# Tax and pay computation (pure, deterministic)
# --------------------------------------------------------------------------------------


def _bracket_tax(taxable: Decimal, brackets: Sequence[Bracket]) -> Decimal:
    """Progressive tax on an annualised amount."""
    tax, lower = ZERO, ZERO
    for upper, rate in brackets:
        if taxable <= lower:
            break
        top = taxable if upper is None else min(taxable, upper)
        tax += (top - lower) * rate
        if upper is None:
            break
        lower = upper
    return tax


def _hourly_hours(profile: EmployeeProfile, period: PayPeriod) -> tuple[Decimal, Decimal, Decimal]:
    """Return (regular, overtime@1.5x, double-time@2x) hours per §2.4–§2.7."""
    by_date = {e.work_date: e.hours for e in profile.timesheet}
    regular = overtime = double = ZERO
    for week in range(2):
        w_reg = w_ot = w_dt = ZERO
        for day_offset in range(7):
            hours = by_date.get(period.start + timedelta(days=week * 7 + day_offset), ZERO)
            if profile.state == "CA":
                w_reg += min(hours, COMPLIANCE.ca_daily_regular)
                w_ot += max(min(hours, COMPLIANCE.ca_daily_double) - COMPLIANCE.ca_daily_regular, ZERO)
                w_dt += max(hours - COMPLIANCE.ca_daily_double, ZERO)
            else:
                w_reg += hours
        excess = max(w_reg - COMPLIANCE.weekly_overtime_threshold, ZERO)
        regular += w_reg - excess
        overtime += w_ot + excess
        double += w_dt
    return regular, overtime, double


def _compute_payroll(inp: PayrollInput, hitl_variance: Decimal) -> PayrollResult:
    """Compute a full payroll result. Raises :class:`TaxCalculationAnomaly` on bad states."""
    emp, period, c = inp.profile, inp.period, COMPLIANCE
    refs: list[str] = ["§1.2", "§1.4", "§9.1"]
    flags: list[str] = []
    confidence = 0.97 - 0.02 * len(inp.adjustments)

    # ---- §2 gross pay -------------------------------------------------------------
    earnings: list[EarningLine] = []
    if emp.pay_type == "salaried":
        assert emp.annual_salary is not None  # guaranteed by model validator
        base = q(emp.annual_salary / c.periods_per_year)
        refs.append("§2.1")
        requested = [a for a in inp.adjustments if a.kind == "prorate"]
        eff_start: Optional[date] = None
        if requested and requested[-1].effective_date:
            eff_start = requested[-1].effective_date
        elif emp.hire_date > period.start:
            eff_start = emp.hire_date
        regular_pay = base
        if eff_start is not None:
            worked = period.working_days(eff_start)
            regular_pay = q(base * D(worked) / D(c.working_days_per_period))
            refs.append("§2.3")
            flags.append(f"PRORATED_{worked}_OF_{c.working_days_per_period}_DAYS")
            confidence -= 0.03
        elif requested:
            flags.append("PRORATION_REQUESTED_BUT_NOT_APPLICABLE")
            confidence -= 0.15
        earnings.append(EarningLine(description="Base salary", amount=regular_pay, ref="§2.1"))
        overtime_pay = ZERO
    else:
        assert emp.hourly_rate is not None
        reg_h, ot_h, dt_h = _hourly_hours(emp, period)
        rate = emp.hourly_rate
        regular_pay = q(reg_h * rate)
        earnings.append(EarningLine(description="Regular hours", hours=q(reg_h), rate=rate,
                                    amount=regular_pay, ref="§2.2"))
        overtime_pay = ZERO
        ot_ref = "§2.5" if emp.state == "CA" else ("§2.6" if emp.state == "TX" else "§2.7")
        if ot_h > 0:
            amt = q(ot_h * rate * c.overtime_multiplier)
            overtime_pay += amt
            earnings.append(EarningLine(description="Overtime (1.5x)", hours=q(ot_h), rate=rate,
                                        amount=amt, ref=ot_ref))
        if dt_h > 0:
            amt = q(dt_h * rate * c.double_time_multiplier)
            overtime_pay += amt
            earnings.append(EarningLine(description="Double time (2.0x)", hours=q(dt_h), rate=rate,
                                        amount=amt, ref="§2.5"))
        refs += ["§2.2", "§2.4", ot_ref]

    # ---- §7 bonus -----------------------------------------------------------------
    bonus = ZERO
    for adj in inp.adjustments:
        if adj.kind == "bonus_pct" and adj.value is not None:
            amt = q(regular_pay * adj.value / 100)
            bonus += amt
            earnings.append(EarningLine(description=f"Bonus ({adj.value}% of regular earnings)",
                                        amount=amt, ref="§7.4"))
        elif adj.kind == "bonus_amount" and adj.value is not None:
            bonus += q(adj.value)
            earnings.append(EarningLine(description="Bonus (fixed amount)",
                                        amount=q(adj.value), ref="§7.4"))
    if bonus > 0:
        refs += ["§7.1", "§7.4", "§7.5"]
    if bonus > c.max_bonus:
        raise TaxCalculationAnomaly(f"{emp.emp_id}: bonus {bonus} exceeds the §7.6 limit")

    regular_wages = q(regular_pay + overtime_pay)
    gross = q(regular_wages + bonus)

    # ---- §3 pre-tax deductions ------------------------------------------------------
    health = q(emp.elections.health_premium)
    refs.append("§3.2")
    remaining_limit = max(c.k401_annual_limit - emp.ytd.k401, ZERO)
    room = max(gross - health, ZERO)
    maxed = any(a.kind == "max_401k" for a in inp.adjustments)
    if maxed:
        k401 = q(min(q(c.k401_annual_limit / c.periods_per_year), remaining_limit, room))
        flags.append("401K_MAXED")
    else:
        k401 = q(min(q(gross * emp.elections.pct_401k / 100), remaining_limit, room))
    if k401 > 0:
        refs.append("§3.3")
    pretax = q(health + k401)
    if pretax > gross:
        raise TaxCalculationAnomaly(f"{emp.emp_id}: pre-tax deductions exceed gross pay (§3.4)")

    # ---- §4 / §6 / §7 income taxes ---------------------------------------------------
    reg_taxable = max(regular_wages - pretax, ZERO)
    leftover = max(pretax - regular_wages, ZERO)
    bonus_taxable = max(bonus - leftover, ZERO)

    annual_fed = max(reg_taxable * c.periods_per_year - c.federal_std_deduction, ZERO)
    fed = q(_bracket_tax(annual_fed, c.federal_brackets) / c.periods_per_year)
    refs += ["§4.1", "§4.2", "§4.3"]
    if bonus_taxable > 0:
        over = min(bonus_taxable, max(emp.ytd.supplemental + bonus_taxable - c.supplemental_threshold, ZERO))
        fed += q((bonus_taxable - over) * c.supplemental_flat_rate + over * c.supplemental_high_rate)
        if over > 0:
            refs.append("§7.2")
            flags.append("SUPPLEMENTAL_OVER_1M_SPLIT")

    rule = STATE_RULES[emp.state]
    annual_state = max(reg_taxable * c.periods_per_year - rule.standard_deduction, ZERO)
    state_tax = q(_bracket_tax(annual_state, rule.brackets) / c.periods_per_year)
    state_tax += q(bonus_taxable * rule.supplemental_rate)
    refs += list(rule.sections if bonus > 0 else rule.sections[:-1])

    # ---- §5 FICA ---------------------------------------------------------------------
    fica_wages = max(gross - health, ZERO)
    ss_room = max(c.ss_wage_base - emp.ytd.ss_wages, ZERO)
    ss = q(min(fica_wages, ss_room) * c.ss_rate)
    medicare = q(fica_wages * c.medicare_rate)
    addl_base = max(emp.ytd.gross + fica_wages - c.addl_medicare_threshold, ZERO) - max(
        emp.ytd.gross - c.addl_medicare_threshold, ZERO
    )
    addl = q(addl_base * c.addl_medicare_rate)
    refs += ["§5.1", "§5.2", "§5.3", "§5.4"]
    if ss == 0 and fica_wages > 0:
        flags.append("SOCIAL_SECURITY_WAGE_BASE_REACHED")

    sdi = q(gross * rule.sdi_rate)
    if rule.sdi_cap is not None:
        sdi = min(sdi, rule.sdi_cap)

    taxes = TaxBreakdown(federal=fed, state=state_tax, social_security=ss, medicare=medicare,
                         additional_medicare=addl, sdi=sdi)

    # ---- §8 garnishments -------------------------------------------------------------
    garnished = ZERO
    if emp.garnishments:
        disposable = max(gross - taxes.total, ZERO)
        floor = q(c.garnish_floor_weekly_multiple * c.federal_min_wage * 2)
        cap_total = q(disposable * c.garnish_combined_pct)
        available = max(gross - pretax - taxes.total, ZERO)
        for g in sorted(emp.garnishments, key=lambda g: g.kind != "child_support"):
            if g.kind == "child_support":
                limit = q(disposable * c.garnish_support_pct)
                refs.append("§8.3")
            else:
                limit = min(q(disposable * c.garnish_creditor_pct), max(disposable - floor, ZERO))
                refs.append("§8.2")
            amount = max(min(g.amount, limit, cap_total - garnished, available - garnished), ZERO)
            if amount < g.amount:
                flags.append(f"GARNISHMENT_CAPPED_{g.case_ref}")
                confidence -= 0.05
            garnished += q(amount)
        refs += ["§8.1", "§8.4"]

    # ---- §9 net pay and controls -----------------------------------------------------
    net = q(gross - pretax - taxes.total - garnished)
    if net < 0:
        raise TaxCalculationAnomaly(f"{emp.emp_id}: negative net pay {net} (§9.1)")
    eff_rate = (taxes.total / gross).quantize(Decimal("0.0001")) if gross > 0 else ZERO
    if gross > 0 and not (c.min_tax_rate <= eff_rate <= c.max_tax_rate):
        flags.append("EFFECTIVE_TAX_RATE_OUT_OF_BAND")
        confidence -= 0.30
    variance = q(gross - emp.prior_period_gross)
    discrepancy = abs(variance) > hitl_variance
    if discrepancy:
        flags.append("PERIOD_OVER_PERIOD_DISCREPANCY")
    refs.append("§9.2")

    try:
        return PayrollResult(
            emp_id=emp.emp_id, full_name=emp.full_name, masked_ssn=emp.masked_ssn, state=emp.state,
            period_start=period.start, period_end=period.end, earnings=earnings, gross_pay=gross,
            k401_deduction=k401, health_deduction=health, taxes=taxes, garnishment=garnished,
            net_pay=net, prior_period_gross=emp.prior_period_gross, variance=variance,
            discrepancy=discrepancy, effective_tax_rate=eff_rate,
            confidence=round(max(min(confidence, 1.0), 0.0), 2), flags=flags,
            compliance_refs=sorted(set(refs), key=lambda r: [int(p) for p in re.findall(r"\d+", r)]),
        )
    except ValidationError as exc:
        raise TaxCalculationAnomaly(f"{emp.emp_id}: impossible state: {exc.errors()[0]['msg']}") from exc


# --------------------------------------------------------------------------------------
# Payslip rendering and (simulated) encrypted delivery
# --------------------------------------------------------------------------------------

TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "assets" / "email_template.html"


def _allowed_domains() -> set[str]:
    raw = os.getenv("ALLOWED_EMAIL_DOMAINS", "acme-corp.example")
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


def _money_filter(value: Any) -> str:
    return f"${q(value):,.2f}"


def build_payslip_context(result: PayrollResult, profile: EmployeeProfile, period: PayPeriod,
                          request_id: str) -> dict[str, Any]:
    """Assemble the Jinja2 context for ``assets/email_template.html`` (masked data only)."""
    t = result.taxes
    return {
        "company_name": os.getenv("COMPANY_NAME", "Acme Corp"),
        "logo_url": os.getenv("COMPANY_LOGO_URL", "https://assets.acme-corp.example/logo.png"),
        "brand_color": os.getenv("COMPANY_BRAND_COLOR", "#0B5FFF"),
        "support_email": os.getenv("PAYROLL_SUPPORT_EMAIL", "payroll-support@acme-corp.example"),
        "employee_name": result.full_name,
        "employee_id": result.emp_id,
        "department": profile.department,
        "masked_ssn": result.masked_ssn,
        "masked_account": profile.masked_account,
        "pay_period_start": period.start.isoformat(),
        "pay_period_end": period.end.isoformat(),
        "pay_date": period.pay_date.isoformat(),
        "earnings": [e.model_dump() for e in result.earnings],
        "pretax_deductions": [
            {"description": "Health premium (Section 125)", "amount": result.health_deduction},
            {"description": "401(k) elective deferral", "amount": result.k401_deduction},
        ],
        "taxes": [
            {"description": "Federal income tax", "amount": t.federal},
            {"description": "State income tax", "amount": t.state},
            {"description": "Social Security", "amount": t.social_security},
            {"description": "Medicare", "amount": t.medicare},
            {"description": "Additional Medicare", "amount": t.additional_medicare},
            {"description": "State disability insurance", "amount": t.sdi},
        ],
        "posttax_deductions": (
            [{"description": "Garnishment (court ordered)", "amount": result.garnishment}]
            if result.garnishment > 0 else []
        ),
        "gross_pay": result.gross_pay,
        "total_pretax": q(result.health_deduction + result.k401_deduction),
        "total_taxes": t.total,
        "total_posttax": result.garnishment,
        "net_pay": result.net_pay,
        "ytd": {"gross": q(profile.ytd.gross + result.gross_pay),
                "k401": q(profile.ytd.k401 + result.k401_deduction)},
        "request_id": request_id,
        "compliance_refs": result.compliance_refs,
    }


def _render_payslip(context: dict[str, Any]) -> str:
    """Render the HTML payslip (Jinja2 with autoescape; plain-text fallback if unavailable)."""
    try:
        from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_PATH.parent)),
            autoescape=select_autoescape(["html"]),
            undefined=StrictUndefined,
        )
        env.filters["money"] = _money_filter
        return env.get_template(TEMPLATE_PATH.name).render(**context)
    except ImportError:
        lines = [f"Payslip {context['employee_id']} {context['masked_ssn']}",
                 f"Gross {_money_filter(context['gross_pay'])}  Net {_money_filter(context['net_pay'])}"]
        return "\n".join(lines)


def _mock_encrypt(payload: bytes, key: bytes) -> bytes:
    """SIMULATED encryption (SHA-256 keystream XOR) standing in for AES-256 PDF encryption.

    This is a demo stand-in and must be replaced by a vetted library in production.
    """
    out = bytearray()
    for block in range(0, len(payload), 32):
        stream = hashlib.sha256(key + block.to_bytes(8, "big")).digest()
        out.extend(b ^ s for b, s in zip(payload[block:block + 32], stream))
    return bytes(out)


async def _send_via_smtp(recipient: str, subject: str, attachment: bytes) -> str:
    """Pretend to hand a message to the enterprise SMTP relay and return a message id."""
    await asyncio.sleep(0.01)  # simulated relay latency
    relay = os.getenv("SMTP_RELAY", "smtp-relay.acme-corp.example:587")
    log.info("smtp_dispatched_simulated", relay=relay, recipient=mask_email(recipient),
             subject=subject, attachment_bytes=len(attachment))
    return f"<{uuid.uuid4().hex}@{relay.split(':')[0]}>"


async def _deliver(result: PayrollResult, profile: EmployeeProfile, period: PayPeriod,
                   role: Role, request_id: str) -> PayslipDeliveryReceipt:
    if role not in RUN_ROLES:
        raise AccessDeniedError(f"role {role.value} may not deliver payslips")
    recipient = profile.work_email.lower()
    domain = recipient.rsplit("@", 1)[-1]
    if domain not in _allowed_domains():
        raise PolicyViolationError(f"recipient domain '{domain}' is not on the allow-list (§9.6)")
    try:
        html = _render_payslip(build_payslip_context(result, profile, period, request_id))
        pdf = b"%PDF-1.7 (simulated)\n" + html.encode("utf-8")
        encrypted = _mock_encrypt(pdf, secrets.token_bytes(32))
        message_id = await _retry_async(
            lambda: _send_via_smtp(recipient, f"Payslip {period.pay_date.isoformat()}", encrypted),
            retry_on=(ConnectionError,), label="smtp",
        )
    except PayrollError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalise any rendering/SMTP failure
        raise PayslipDeliveryError(f"{profile.emp_id}: {type(exc).__name__}: {exc}") from exc
    return PayslipDeliveryReceipt(
        message_id=message_id, emp_id=profile.emp_id, recipient_masked=mask_email(recipient),
        encrypted=True, pdf_sha256=hashlib.sha256(encrypted).hexdigest(), pdf_bytes=len(encrypted),
        smtp_relay=os.getenv("SMTP_RELAY", "smtp-relay.acme-corp.example:587"),
        status="queued", sent_at=datetime.now(timezone.utc),
    )


# --------------------------------------------------------------------------------------
# Public async functions + LangChain @tool wrappers
# --------------------------------------------------------------------------------------

_T = TypeVar("_T", bound=BaseModel)


def _coerce(model: type[_T], value: Any) -> _T:
    return value if isinstance(value, model) else model.model_validate(value)


async def _extract(emp_ids: Sequence[str], department: Optional[str], state: Optional[str],
                   ctx: RequestContext, period: PayPeriod) -> dict[str, Any]:
    if ctx.role not in RUN_ROLES:
        raise AccessDeniedError(f"role {ctx.role.value} may not extract payroll data")
    hris = get_hris()
    ids = list(dict.fromkeys(emp_ids))
    if department or state:
        derived = await _retry_async(lambda: hris.find_ids(department, state), label="hris.find_ids")
        if ctx.role is not Role.PAYROLL_ADMIN:
            executives = hris.executive_ids()  # filter-derived scope never escalates (§9.4)
            derived = [i for i in derived if i not in executives]
        ids = list(dict.fromkeys([*ids, *derived]))
    if not ids:
        raise EmployeeNotFoundError([])
    log.info("hris_extract_start", request_id=ctx.request_id, count=len(ids), role=ctx.role.value)

    async def one(emp_id: str) -> EmployeeRecord:
        return await _retry_async(lambda: hris.fetch(emp_id), label=f"hris.fetch:{emp_id}")

    outcomes = await asyncio.gather(*(one(i) for i in ids), return_exceptions=True)
    missing = [i for i, o in zip(ids, outcomes) if isinstance(o, EmployeeNotFoundError)]
    for o in outcomes:
        if isinstance(o, HRISUnavailableError):
            raise o
        if isinstance(o, BaseException) and not isinstance(o, EmployeeNotFoundError):
            raise o
    if missing:
        raise EmployeeNotFoundError(missing)
    profiles: list[EmployeeProfile] = []
    for rec in outcomes:
        assert isinstance(rec, EmployeeRecord)
        if rec.is_executive and ctx.role is not Role.PAYROLL_ADMIN:
            raise AccessDeniedError(f"{rec.emp_id} is an executive record (§9.4)")
        profiles.append(rec.to_profile())
    log.info("hris_extract_done", request_id=ctx.request_id, profiles=len(profiles))
    return {"profiles": [p.model_dump(mode="json") for p in profiles],
            "period": period.model_dump(mode="json")}


class ExtractArgs(BaseModel):
    """Arguments for :func:`extract_hris_data`."""

    emp_ids: list[str] = Field(default_factory=list, max_length=500)
    department: Optional[str] = Field(default=None, max_length=64)
    state: Optional[StateCode] = None
    request_context: RequestContext
    period: PayPeriod


@tool("extract_hris_data", args_schema=ExtractArgs)
async def extract_hris_data(emp_ids: list[str], department: Optional[str], state: Optional[str],
                            request_context: RequestContext, period: PayPeriod) -> dict[str, Any]:
    """Fetch PII-minimised employee profiles from the HRIS with retry and RBAC checks.

    Returns ``{"profiles": [...], "period": {...}}``. Raises ``EmployeeNotFoundError``,
    ``AccessDeniedError`` or ``HRISUnavailableError``.
    """
    return await _extract(emp_ids, department, state, _coerce(RequestContext, request_context),
                          _coerce(PayPeriod, period))


class CalculateArgs(BaseModel):
    """Arguments for :func:`calculate_payroll_taxes`."""

    payroll_input: PayrollInput
    hitl_variance_threshold: Money = D("10000")


@tool("calculate_payroll_taxes", args_schema=CalculateArgs)
async def calculate_payroll_taxes(payroll_input: PayrollInput,
                                  hitl_variance_threshold: Decimal = D("10000")) -> dict[str, Any]:
    """Compute gross-to-net pay: overtime, proration, bonus, pre-tax, taxes, garnishments.

    Rates derive exclusively from ``reference/compliance_rules.md``. Returns a validated
    ``PayrollResult`` (JSON mode). Raises ``TaxCalculationAnomaly`` on impossible states.
    """
    inp = _coerce(PayrollInput, payroll_input)
    await asyncio.sleep(0)  # yield to the loop between employees in a batch
    result = _compute_payroll(inp, D(hitl_variance_threshold))
    log.info("payroll_calculated", emp_id=result.emp_id, confidence=result.confidence,
             flags=result.flags, discrepancy=result.discrepancy)
    return result.model_dump(mode="json")


class DeliverArgs(BaseModel):
    """Arguments for :func:`deliver_secure_payslip`."""

    result: PayrollResult
    profile: EmployeeProfile
    period: PayPeriod
    role: Role
    request_id: str = Field(min_length=8, max_length=64)


@tool("deliver_secure_payslip", args_schema=DeliverArgs)
async def deliver_secure_payslip(result: PayrollResult, profile: EmployeeProfile, period: PayPeriod,
                                 role: Role, request_id: str) -> dict[str, Any]:
    """Render, encrypt (simulated) and dispatch a payslip to the employee's corporate mailbox.

    Only allow-listed corporate domains are accepted (§9.6). Returns a
    ``PayslipDeliveryReceipt``. Raises ``AccessDeniedError``, ``PolicyViolationError`` or
    ``PayslipDeliveryError``.
    """
    receipt = await _deliver(_coerce(PayrollResult, result), _coerce(EmployeeProfile, profile),
                             _coerce(PayPeriod, period), Role(role), request_id)
    return receipt.model_dump(mode="json")
