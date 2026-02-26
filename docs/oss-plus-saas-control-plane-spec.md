# Rustaccio OSS + SaaS Control Plane Specification

Status: Draft v1  
Date: 2026-02-26

## 1. Purpose

Define a product and architecture model where:

1. `rustaccio` remains fully open source and best-in-class for self-hosted and small deployments.
2. A separate closed-source SaaS control plane provides hosted, commercial-grade operations for private npm distribution, including paid package workflows.
3. Both offerings share one npm data-plane runtime and one compatibility target: npm-first developer experience.

## 2. Product Model

### 2.1 Open Source Offering (Rustaccio OSS)

Rustaccio OSS is the data plane and must remain:

1. Fully functional for small and medium self-hosted deployments.
2. Safe and easy by default (`local` profile, minimal infra dependencies).
3. Compatible with managed deployments through explicit mode gates.

Rustaccio OSS remains authoritative for:

1. npm protocol routes and package operations.
2. Tarball/metadata persistence behavior.
3. Auth and policy extension interfaces.
4. Registry runtime controls (rate limiting, quota, state coordination, metrics backends).

### 2.2 Hosted SaaS Offering (Closed Source)

The control plane is a separate repository/service and owns:

1. Multi-tenant account and organization management.
2. Billing, subscriptions, invoicing, and usage metering.
3. Licensing and entitlements for commercial package distribution.
4. Tenant provisioning, policy orchestration, and admin UX.
5. Audit trails, analytics, and enterprise controls.
6. SLA operations (incident tooling, backups, SRE automation, support workflows).

## 3. Core Principles

1. No feature degradation in OSS to force SaaS migration.
2. Managed/SaaS-specific strictness must be additive and explicitly gated.
3. Data-plane and control-plane contracts must be versioned and backward compatible.
4. npm client UX must stay first-class in both OSS and SaaS paths.
5. Security and auditability are baseline requirements for hosted mode.

## 4. Architecture

## 4.1 Components

1. Rustaccio Data Plane (OSS): serves npm API, package storage, authz decisions, package mutation pipeline.
2. Control Plane API (Closed): tenant lifecycle, billing, licensing, entitlement graph, policy authoring, audit/event processing.
3. Identity Provider(s): customer-facing login and machine tokens.
4. Billing Provider(s): payment and subscription system.
5. Metadata Store (SaaS evolution): transactional store for package/user/token metadata for hosted reliability.
6. Object Storage: immutable tarball blob storage.

## 4.2 Integration Boundaries

Rustaccio integrates with control plane through existing and extended contracts:

1. Auth contract: request authentication and identity resolution.
2. Policy contract: allow/deny decisions for read/publish/unpublish/admin actions.
3. Event contract (new): structured registry events for audit, analytics, billing metering, and support diagnostics.
4. Provisioning contract (new): machine-readable tenant/runtime config bundle generation.

## 4.3 Deployment Topologies

Phase A (initial SaaS):

1. Single-tenant or strongly isolated per-tenant Rustaccio instances.
2. Control plane provisions runtime env/config and manages lifecycle.

Phase B (scale SaaS):

1. Pooled multi-tenant control plane.
2. Data-plane tenancy remains strongly isolated by shard/cluster and policy boundary.

## 5. Capability Split (OSS vs SaaS)

Always OSS:

1. npm-compatible registry APIs.
2. Local/simple deployment path.
3. Managed mode runtime guardrails and feature flags.
4. Local and external auth/policy backend support.
5. Core observability hooks and admin repair endpoints.

SaaS-only (closed-source control plane):

1. Billing connectors and subscription lifecycle.
2. Commercial licensing and entitlement orchestration.
3. Customer portal for package purchase, access recovery, token self-service.
4. Org/team management, role templates, enterprise policy packs.
5. Hosted analytics, audit explorer, SLA and support tooling.

## 6. Gap Closure Plan

This section addresses the current competitive gaps identified against commercial npm distribution platforms.

### 6.1 Licensing and Entitlements

Add closed-source control-plane domain model:

1. `Product`: sellable package group.
2. `Plan`: access level/limits.
3. `Entitlement`: org/user rights to package scopes/versions.
4. `Credential`: npm token/license binding and rotation policy.

Required runtime behavior:

1. Rustaccio validates token identity through external auth hook.
2. Policy decision includes entitlement context for package/version action.
3. Revocation propagates within strict SLA (target: under 60 seconds).

### 6.2 Billing and Commercial Flow

Control plane must support:

1. Checkout to entitlement provisioning.
2. Subscription lifecycle to access enforcement.
3. Invoice and payment-failure state to policy outcomes.

Developer UX targets:

1. “Buy package -> install with npm” in under 5 minutes.
2. Token recovery and rotation without support ticket.

### 6.3 Reliability and Consistency

Current known limitation: metadata writes are non-transactional in sidecar model.

SaaS roadmap requirement:

1. Introduce transactional metadata system for hosted path.
2. Keep blob storage for immutable tarballs.
3. Add conflict-safe write semantics and cache invalidation strategy.

Transition rule:

1. OSS sidecar model stays supported.
2. SaaS reliability path can add optional metadata backend without breaking OSS mode.

### 6.4 Audit and Compliance

Add event/audit model:

1. Auth events: login/token issuance/revocation/failures.
2. Package events: publish, unpublish, dist-tag, owner changes, tarball delete.
3. Admin events: policy/config changes, reindex, storage health actions.

Minimum compliance features for SaaS:

1. Immutable audit log retention controls.
2. Export API for customer compliance tooling.
3. Per-event actor, tenant, package, request-id metadata.

### 6.5 npm DX Improvements

World-class npm-first experience requires:

1. First-party onboarding flow (`.npmrc` bootstrap, token issue, scope setup).
2. Fast and clear auth errors with actionable remediation.
3. Publish/install diagnostics with correlation IDs.
4. Stable token model for CI/CD and local workflows.
5. High-quality docs and copy-paste integrations for npm/pnpm/yarn/bun.

## 7. Data-Plane Contract Requirements

Rustaccio should provide stable, documented interfaces for control-plane integration.

Required contract stability:

1. Auth request contract (token + method + path -> identity/groups).
2. Policy decision contract (subject, action, resource -> allow/deny/reason).
3. Admin and diagnostics API stability.
4. Versioned event schema (when event stream is added).

Operational requirements:

1. Correlation IDs on all request paths.
2. Consistent error code taxonomy for auth/policy/storage/upstream failures.
3. Clear fail-open/fail-closed semantics by feature area.

## 8. Security Model

1. Control plane and data plane communicate over mutually authenticated channels.
2. Tenant identity and authorization are externalized and centrally managed.
3. Secrets are rotated automatically and scoped per tenant/environment.
4. Admin operations require explicit principal constraints in managed mode.
5. Least-privilege access for storage and backend services.

## 9. Migration and Compatibility

1. Existing OSS users remain on current runtime profiles without forced migration.
2. SaaS users can import existing package data and token identities where possible.
3. Configuration migration tools should map OSS env/config to hosted project settings.
4. Backward-compatible defaults are mandatory for minor Rustaccio releases.

## 10. Roadmap

### Phase 0: Foundation (Now)

1. Freeze OSS/SaaS boundary contract in docs.
2. Add control-plane integration test harness against current auth/policy hooks.
3. Define event schema and error taxonomy.

Exit criteria:

1. Contract tests pass in CI for both simple and managed modes.

### Phase 1: Commercial MVP

1. Closed control plane: orgs, projects, tokens, billing integration, entitlements.
2. SaaS onboarding and package purchase-to-install path.
3. Initial audit log and support diagnostics.

Exit criteria:

1. New customer can purchase and install private package in under 5 minutes.
2. Entitlement revoke effective under 60 seconds.

### Phase 2: Reliability Hardening

1. Hosted metadata reliability upgrade (transactional store path).
2. Conflict-safe mutation semantics.
3. Formal SLOs and error budgets.

Exit criteria:

1. Publish consistency SLO met for hosted tenants.

### Phase 3: Enterprise and Differentiation

1. Compliance exports, policy packs, advanced RBAC.
2. Tenant analytics and usage insights.
3. Advanced package commerce features (versioned entitlements, trial flows, seat models).

Exit criteria:

1. Enterprise feature set closes top procurement blockers.

## 11. Success Metrics

OSS success:

1. Time to first publish in local mode.
2. Weekly active self-hosted instances.
3. Upgrade success rate and backward compatibility incidents.

SaaS success:

1. Time from signup to first successful install.
2. Entitlement enforcement latency.
3. Publish/install success rate.
4. Support ticket rate per active tenant.
5. MRR growth and retention for commercial package sellers.

## 12. Immediate Next Actions

1. Approve this boundary and roadmap at product/engineering level.
2. Open an OSS issue set for contract hardening:
   - event schema
   - correlation IDs
   - error taxonomy
   - auth/policy contract docs
3. Start control-plane repo with domain models:
   - tenant/org/project
   - product/plan/entitlement
   - credential/token lifecycle
4. Build end-to-end “paid package install” reference flow before broad feature expansion.
