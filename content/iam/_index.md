---
title: "IAM"
linkTitle: "IAM"
description: "Vendor-neutral IAM blueprints: OAuth 2.1, OIDC, SAML, passkeys (WebAuthn), multi-tenant RBAC/ABAC, workload identity federation and secure JWT lifecycles."
weight: 2
cascade:
  type: docs
---

# Identity & Access Management

Most breaches involve stolen credentials, over-broad tokens or weak session handling. These blueprints cover how to authenticate and authorize users and workloads with open standards, short-lived tokens and phishing-resistant methods.

**Who this is for:** backend and platform engineers, security architects and SaaS founders building login, SSO and access control.

## Start Here: Learning Path

1. **OAuth 2.1 vs. OIDC vs. SAML 2.0** *(infographic, coming soon)*: side-by-side sequence flows and token exchange rules.
2. **Implementing Passkeys (WebAuthn) from Scratch** *(coming soon)*: a phishing-resistant FIDO2 login flow.
3. **Multi-Tenant RBAC & ABAC Architecture** *(coming soon)*: database schemas and policy evaluation logic.
4. **Workload Identity Federation in CI/CD** *(coming soon)*: replace static AWS and GCP keys with OIDC tokens.
5. **Secure JWT Lifecycle Management** *(coming soon)*: short TTLs, refresh token rotation and revocation lists.

## Core Principles

- **Prefer open standards.** OIDC and OAuth 2.1 over custom login schemes.
- **Keep tokens short-lived and narrowly scoped.** Validate signature, audience and scope on every request.
- **Bind credentials to the user.** Passkeys and proof-of-possession beat shared secrets.
- **Authorize on the server.** Deny by default, and test the denials.
- **Log authentication and authorization decisions.** Both successes and failures.

## Related Pillars

- [AI Security](/ai-security/): securing agents and LLM-backed APIs
- [PAM](/pam/): ephemeral access and non-human identity governance
- [Product Dev](/product-dev/): API authorization and audit logging

---

*All content is for educational and defensive security engineering purposes. Validate controls in staging before production.*
