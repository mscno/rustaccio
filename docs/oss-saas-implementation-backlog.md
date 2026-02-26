# Rustaccio OSS + SaaS Backlog (Split by Repo)

Status: Draft v1  
Date: 2026-02-26  
Related: `docs/oss-plus-saas-control-plane-spec.md`

## 1. Scope

This backlog converts the OSS + SaaS control-plane spec into execution-ready work split across:

1. `rustaccio` (open-source data plane repo)
2. `control-plane` (closed-source SaaS repo)

## 2. Milestones

1. M0: Contract hardening and integration baseline
2. M1: Commercial MVP (paid package install flow)
3. M2: Reliability and consistency hardening
4. M3: Enterprise and differentiation

## 3. Labels and Priority

Use labels:

1. `area/auth`
2. `area/policy`
3. `area/events`
4. `area/reliability`
5. `area/dx`
6. `area/billing`
7. `area/entitlements`
8. `area/audit`

Priority:

1. `P0`: blocks MVP or safety
2. `P1`: required for competitive SaaS
3. `P2`: optimization and differentiation

## 4. OSS Repo Backlog (`rustaccio`)

## Epic OSS-1: Data-plane Contract Hardening (M0)

### OSS-1.1 (P0) Define versioned auth contract doc

1. Add `docs/contracts/auth-request-v1.md`.
2. Specify request/response schema and error semantics for external auth.
3. Include timeout/fail behavior and required headers.

Acceptance:

1. Doc published with examples for success, unauthenticated, backend error.
2. Integration tests cover contract examples.

### OSS-1.2 (P0) Define versioned policy contract doc

1. Add `docs/contracts/policy-decision-v1.md`.
2. Specify subject/action/resource model and allow/deny response schema.
3. Define fail-open/fail-closed behavior matrix.

Acceptance:

1. Doc published and referenced from README.
2. Existing policy integration tests map to contract cases.

### OSS-1.3 (P0) Correlation IDs on all requests

1. Emit request correlation ID on each API response header.
2. Ensure structured logs include the same ID.
3. Propagate ID to auth/policy outgoing requests.

Acceptance:

1. Middleware unit tests confirm header emission.
2. Integration tests confirm propagation to mock auth/policy services.

### OSS-1.4 (P0) Error taxonomy normalization

1. Define stable error code set (`AUTH_*`, `POLICY_*`, `STORAGE_*`, `UPSTREAM_*`).
2. Standardize error payload shape for operational diagnosis.
3. Map existing failures to taxonomy.

Acceptance:

1. API docs include error code table.
2. Tests assert representative codes for each major failure class.

## Epic OSS-2: Event and Audit Foundation (M1)

### OSS-2.1 (P1) Registry event schema v1

1. Add event model for publish/unpublish/dist-tag/owner/token/admin actions.
2. Include tenant/project placeholders for SaaS correlation.
3. Include actor, package, request ID, timestamp, outcome.

Acceptance:

1. Schema doc and Rust type definitions are added.
2. Event serialization tests added.

### OSS-2.2 (P1) Pluggable event sink interface

1. Add trait for sink implementations (`none`, `http`, `queue` future-ready).
2. Emit events from existing mutation paths.
3. Preserve low overhead in simple mode.

Acceptance:

1. Default `none` keeps current behavior/perf.
2. Integration test validates event delivery to mock HTTP sink.

## Epic OSS-3: Commercial npm DX Improvements (M1)

### OSS-3.1 (P1) First-party npm bootstrap endpoint/docs

1. Add endpoint or helper payload for `.npmrc` bootstrap.
2. Support scope + registry URL + token format guidance.
3. Add copy-paste docs for npm/pnpm/yarn/bun.

Acceptance:

1. New docs page with tested commands.
2. Integration test verifies response shape if endpoint added.

### OSS-3.2 (P1) Auth error UX upgrade

1. Improve auth failure responses with actionable remediation messages.
2. Keep error codes machine-parsable.
3. Add docs for common auth failure recovery steps.

Acceptance:

1. Tests assert message/code for invalid token, expired token, no entitlement.

## Epic OSS-4: Hosted Reliability Path (M2)

### OSS-4.1 (P0) Metadata backend abstraction for transactional path

1. Introduce abstraction for metadata persistence beyond sidecars.
2. Keep sidecar backend as default OSS path.
3. Add capability flags to prevent accidental activation without config.

Acceptance:

1. No regression in existing sidecar tests.
2. New abstraction has trait tests and migration boundary docs.

### OSS-4.2 (P0) Conflict-safe mutation semantics

1. Add compare-and-swap/version checks in mutation pipeline where feasible.
2. Provide deterministic conflict errors for concurrent writes.
3. Emit conflict events/metrics.

Acceptance:

1. Concurrency integration tests prove conflict handling behavior.

### OSS-4.3 (P1) Cache invalidation hooks for multi-node consistency

1. Add event-driven invalidation hook point.
2. Support fallback periodic refresh behavior.
3. Document staleness bounds by mode.

Acceptance:

1. Multi-node tests validate reduced stale-read window under invalidation.

## 5. Closed Repo Backlog (`control-plane`)

## Epic CP-1: Tenant and Project Core (M0)

### CP-1.1 (P0) Tenant/org/project domain model

1. Create entities: org, user, project, environment.
2. Add RBAC baseline (owner/admin/member/billing).
3. Add API and persistence schema migrations.

Acceptance:

1. CRUD API for org/project/environment with authz tests.

### CP-1.2 (P0) Runtime provisioning pipeline

1. Define deployment manifest generated for Rustaccio per environment.
2. Provision auth/policy endpoints and secrets.
3. Store immutable config revisions.

Acceptance:

1. Reproducible deployment revision history.
2. Rollback to previous config revision works.

## Epic CP-2: Billing and Entitlements (M1)

### CP-2.1 (P0) Product/plan/entitlement model

1. Create sellable product and plan entities.
2. Model entitlement grants by package scope/version rules.
3. Expose entitlement lookup API for policy engine.

Acceptance:

1. Policy lookup returns deterministic allow/deny with reason.

### CP-2.2 (P0) Stripe integration (initial provider)

1. Checkout session creation.
2. Webhook ingestion for purchase/renewal/cancel/failure.
3. Entitlement lifecycle updates from billing events.

Acceptance:

1. End-to-end: purchase creates entitlement and enables npm install.
2. Failed payment eventually revokes entitlement per policy.

### CP-2.3 (P0) Credential issuance and rotation

1. Issue short-lived and long-lived npm credentials by policy.
2. Self-service rotate/revoke UI/API.
3. Machine token path for CI/CD.

Acceptance:

1. Revocation reflected in data-plane auth under target SLA.

## Epic CP-3: Customer and Developer UX (M1)

### CP-3.1 (P1) Onboarding wizard

1. Create project, package scope, token, `.npmrc` snippet.
2. Validate install and publish path during onboarding.
3. Include npm/pnpm/yarn/bun tabs.

Acceptance:

1. New user reaches first private install in under 5 minutes in usability test.

### CP-3.2 (P1) Seller portal basics

1. Package listing, access grants, customer entitlements.
2. Revenue/event summary cards.
3. Common support actions (reissue token, revoke access, replay webhook).

Acceptance:

1. Seller can manage a customer access issue without staff intervention.

## Epic CP-4: Audit, Compliance, and Ops (M2)

### CP-4.1 (P1) Immutable audit log pipeline

1. Ingest registry events and control-plane events.
2. Retention policy and tamper-evident storage strategy.
3. Export API (CSV/JSON).

Acceptance:

1. Audit event query by actor/package/request ID.
2. Export works for defined date range and org scope.

### CP-4.2 (P1) SLOs and incident tooling

1. Define SLOs: auth latency, publish success, install success.
2. Alerting and on-call runbooks.
3. Customer-facing status and incident timeline integration.

Acceptance:

1. SLO dashboards live with alert thresholds.
2. Incident drill executed with postmortem template.

## Epic CP-5: Enterprise Differentiation (M3)

### CP-5.1 (P2) Advanced RBAC and policy packs

1. Custom roles.
2. Environment-scoped policy templates.
3. Approval workflows for sensitive actions.

### CP-5.2 (P2) Advanced commercial models

1. Seat-based and usage-based entitlement variants.
2. Trial and grace-period policy controls.
3. Version-gated entitlements by semver range.

## 6. Cross-Repo Integration Issues

### X-1 (P0) Contract test suite

1. Add black-box integration tests that run control-plane mocks against Rustaccio.
2. Validate auth, policy, error taxonomy, and correlation IDs.

Acceptance:

1. CI gate blocks releases on contract break.

### X-2 (P0) Versioned compatibility matrix

1. Publish compatibility table (`rustaccio version` x `control-plane version`).
2. Define support windows and deprecation policy.

Acceptance:

1. Matrix published and referenced in release process.

### X-3 (P1) End-to-end paid install reference flow

1. Automated flow: buy -> entitlement grant -> token issue -> npm install.
2. Include revocation and retry scenarios.

Acceptance:

1. E2E suite green in CI with deterministic fixtures.

## 7. Execution Order (Recommended)

1. Start with `OSS-1` + `CP-1` + `X-1`.
2. Move to `CP-2` and `OSS-3` for commercial MVP.
3. Add `OSS-2` + `CP-4` for audit/compliance baseline.
4. Complete `OSS-4` before broad multi-tenant scale-out.
5. Deliver `CP-5` after MVP retention and enterprise feedback.

## 8. Definition of Done Per Issue

1. Code and docs updated.
2. Tests added/updated for behavior change.
3. No warnings introduced.
4. Rustaccio repo validation passes:
   - `just check`
   - `cargo test --workspace --all-targets --locked`
5. For release gates, run full matrix from `AGENTS.md`.

