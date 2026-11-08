# Acme Corp Enterprise Payroll Compliance Manual (FY2026 — MOCK)

> **DISCLAIMER.** This manual is synthetic reference data for the Payroll Automation Skill. Rates, brackets and
> limits are *mock* values, loosely modelled on US practice. They are **not tax or legal advice** and must never be
> used for real payroll. The code in `scripts/tools.py` (`COMPLIANCE`) mirrors this document one-to-one; every
> calculation cites the section (`§x.y`) it derives from. An answer that uses a rate not stated here is a
> hallucination.

## §1 Scope and Conventions

- **§1.1 Pay frequency.** All employees are paid **biweekly: 26 periods per year**. A period runs Monday–Sunday for two
  weeks and contains **10 working days** (Mon–Fri).
- **§1.2 Currency and rounding.** USD. Every monetary line is rounded **half-up to the cent** (`ROUND_HALF_UP`) when it
  is produced. Rounding is never deferred to the net-pay line.
- **§1.3 Jurisdictions covered.** Federal, **California (CA)**, **New York (NY)** and **Texas (TX)**. Work-state rules
  apply (the state in the employee's HRIS record).
- **§1.4 Calculation order.** Gross pay → pre-tax deductions → taxes → garnishments → net pay (see §9.1).

## §2 Gross Pay

- **§2.1 Salaried employees.** Per-period base = `annual_salary / 26`.
- **§2.2 Hourly employees.** Regular pay = regular hours × hourly rate; overtime hours are paid at the multipliers in
  §2.4–§2.7.
- **§2.3 Proration (mid-cycle hire or explicit request).** Prorated base =
  `per-period base × (working days from effective start date to period end ÷ 10)`. The effective start date is the
  later of the hire date and the period start, unless the payroll request supplies an explicit effective date. Working
  days are Monday–Friday only.
- **§2.4 Federal overtime (FLSA).** Hours over **40 in a Monday–Sunday workweek** are paid at **1.5×** the regular
  rate. No daily overtime applies federally.
- **§2.5 California overtime.** In addition to the weekly rule in §2.4:
  - hours **over 8 and up to 12 in a workday** are paid at **1.5×**;
  - hours **over 12 in a workday** are paid at **2.0× (double time)**;
  - weekly hours over 40 that were *not already* paid as daily overtime are paid at 1.5×.
  - Seventh-consecutive-day premiums are **out of scope** for this skill and require human review.
- **§2.6 Texas overtime.** Texas follows the federal rule only (§2.4). A 13-hour day in Texas is straight time unless
  weekly hours exceed 40.
- **§2.7 New York overtime.** New York follows the federal weekly rule (§2.4) for the covered non-exempt staff in
  scope here.

## §3 Pre-Tax Deductions

- **§3.1 Order.** Pre-tax deductions are applied in this order: (1) health premium, (2) 401(k) elective deferral.
- **§3.2 Health premium (Section 125).** A fixed per-period amount from the HRIS record. It reduces federal taxable
  wages, state taxable wages and FICA wages.
- **§3.3 401(k) elective deferral.**
  - Annual elective limit: **$24,500**. Per-period maximum: `24,500 / 26 = $942.31`.
  - Normal deferral = `election % × eligible compensation` (regular + overtime + bonus), never more than the remaining
    annual limit (`24,500 − YTD deferrals`) and never more than gross pay minus the health premium.
  - **"Maxed" deferral** (explicit request): `min(per-period maximum $942.31, remaining annual limit, gross − health)`.
  - 401(k) deferrals reduce federal and state taxable wages but **do not reduce FICA wages**.
- **§3.4 Impossible states.** Pre-tax deductions greater than gross pay are a calculation anomaly and must never be
  paid out.

## §4 Federal Income Tax Withholding

- **§4.1 Method.** Annualised percentage method on *regular* wages (all earnings except bonus):
  `annual taxable = max(regular taxable wages × 26 − $15,000, 0)`; tax is computed on the brackets in §4.2 and divided
  by 26.
- **§4.2 Brackets (single, annualised).**

  | Taxable income over | Up to | Rate |
  |---|---|---|
  | $0 | $11,925 | 10% |
  | $11,925 | $48,475 | 12% |
  | $48,475 | $103,350 | 22% |
  | $103,350 | $197,300 | 24% |
  | $197,300 | $250,525 | 32% |
  | $250,525 | $626,350 | 35% |
  | $626,350 | — | 37% |
- **§4.3 Standard deduction.** $15,000 annualised for every employee (mock; no W-4 variations are modelled).

## §5 FICA

- **§5.1 Social Security.** **6.2%** of FICA wages up to the annual wage base of **$184,500**. If YTD Social Security
  wages already reached the base, withhold **$0**. Only the portion of this period's wages below the base is taxed.
- **§5.2 Medicare.** **1.45%** of all FICA wages, with no cap.
- **§5.3 Additional Medicare.** An extra **0.9%** on FICA wages above **$200,000 of YTD Medicare wages**; only the
  portion of this period's wages that crosses the threshold is taxed.
- **§5.4 FICA wages.** Gross pay minus Section 125 health premiums. 401(k) deferrals are *not* subtracted (§3.3).

## §6 State Taxes

- **§6.1 Texas.** No state income tax and no state disability insurance. State withholding is $0.
- **§6.2 California income tax.** Annualised: `max(regular taxable wages × 26 − $5,540, 0)` taxed on:

  | Over | Up to | Rate |
  |---|---|---|
  | $0 | $10,756 | 1.0% |
  | $10,756 | $25,499 | 2.0% |
  | $25,499 | $40,245 | 4.0% |
  | $40,245 | $55,866 | 6.0% |
  | $55,866 | $70,606 | 8.0% |
  | $70,606 | $360,659 | 9.3% |
  | $360,659 | — | 12.3% |
- **§6.3 California SDI.** **1.2%** of gross pay, no wage cap (mock).
- **§6.4 New York income tax.** Annualised: `max(regular taxable wages × 26 − $8,000, 0)` taxed on:

  | Over | Up to | Rate |
  |---|---|---|
  | $0 | $8,500 | 4.00% |
  | $8,500 | $11,700 | 4.50% |
  | $11,700 | $13,900 | 5.25% |
  | $13,900 | $80,650 | 5.50% |
  | $80,650 | $215,400 | 6.00% |
  | $215,400 | — | 6.85% |
- **§6.5 New York SDI.** **0.5%** of gross pay, capped at **$1.20 per biweekly period** ($0.60/week).

## §7 Supplemental Wages and Bonus Withholding

- **§7.1 Federal flat rate.** Bonuses are supplemental wages withheld at a flat **22%** (no annualisation).
- **§7.2 Over $1 million.** Once YTD supplemental wages exceed **$1,000,000**, the portion above the threshold is
  withheld at **37%**. If the threshold was already exceeded, the full bonus is withheld at 37%. A bonus that crosses
  the threshold is split: the part up to $1,000,000 at 22%, the remainder at 37%.
- **§7.3 State supplemental rates.** **CA 10.23%**, **NY 11.70%**, **TX 0%**, applied to the bonus.
- **§7.4 Percentage bonuses.** A "N% bonus" is **N% of the employee's regular earnings for the period** (base pay
  after any proration; overtime excluded). A fixed-amount bonus is paid exactly as stated.
- **§7.5 FICA.** Bonuses are fully subject to FICA (§5). Pre-tax deductions are applied to regular wages first; any
  remainder reduces the bonus's taxable amount.
- **§7.6 Limits.** A single bonus may not exceed **$5,000,000** and a percentage bonus may not exceed **100%**.

## §8 Garnishments

- **§8.1 Disposable earnings.** Gross pay minus legally required taxes (federal, state, Social Security, Medicare,
  additional Medicare, SDI). Voluntary and pre-tax deductions (401(k), health) are *not* subtracted.
- **§8.2 Creditor garnishment (CCPA).** Maximum withholding per period is the **lesser of**:
  1. **25% of disposable earnings**, or
  2. disposable earnings **minus 30 × the federal minimum wage per week**. Federal minimum wage is $7.25, so the
     floor is $217.50 per week, **$435.00 per biweekly period**.
- **§8.3 Child support.** Maximum **50% of disposable earnings** (employee supports another dependent).
- **§8.4 Priority and combined limit.** Child support is withheld first. Total garnishments in a period may not exceed
  **50% of disposable earnings**. Withholding is the lesser of the court-ordered amount and the applicable limit; any
  unpaid remainder is *not* carried forward automatically.

## §9 Net Pay and Controls

- **§9.1 Net pay.** `gross − 401(k) − health − (federal + state + SS + Medicare + additional Medicare + SDI) −
  garnishments`. Net pay must never exceed gross pay or be negative.
- **§9.2 Human-in-the-loop (HITL) triggers.** A run must pause for human review when **any** of the following holds:
  - model confidence is **below 0.85**;
  - gross pay differs from the prior period by **more than $10,000** (either direction);
  - the effective total tax rate falls outside **5%–55%** of gross pay.
- **§9.3 Four-eyes principle.** The human reviewer must be a different identity from the requester.
- **§9.4 Executive compensation.** Records flagged executive may be processed only by the `PAYROLL_ADMIN` role.
- **§9.5 Immutable inputs.** This skill never changes base salary, pay rates, bank details or elections. Requests to
  do so are rejected, not queued.
- **§9.6 Distribution.** Payslips go only to the employee's corporate address (`acme-corp.example`), encrypted. No
  other recipients are permitted.
- **§9.7 PII.** SSNs are shown as `XXX-XX-####` and bank accounts as `****####` in every output and log.

## §10 Worked Edge Cases

- **§10.1 New hire mid-cycle.** Hired Monday of week 2: 5 of 10 working days → base × 0.5 (§2.3).
- **§10.2 California 13-hour day.** 8 regular + 4 at 1.5× + 1 at 2.0× for that day (§2.5), then the weekly 40-hour test
  on the remaining regular hours.
- **§10.3 Texas 45-hour week.** 40 regular + 5 at 1.5× (§2.6); no daily test.
- **§10.4 401(k) near the limit.** With $24,000 deferred YTD, only $500 may be deferred even if the election would
  produce more (§3.3).
- **§10.5 Executive past the wage base.** Social Security is $0 once YTD Social Security wages reach $184,500, while
  Medicare and Additional Medicare keep applying (§5).
- **§10.6 Bonus crossing $1M supplemental.** Split at 22% / 37% (§7.2).
- **§10.7 Garnishment exceeding the cap.** A $800 creditor order against low disposable pay is cut to the §8.2 limit.
