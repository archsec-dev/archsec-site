---
title: "Product Dev"
linkTitle: "Product Dev"
description: "Vendor-neutral secure product development blueprints: shift-left DevSecOps, secrets scanning and SBOMs, STRIDE threat modeling, BOLA defense and tamper-proof audit logs."
weight: 4
cascade:
  type: docs
---

# Secure Product Development

Security is cheapest when it is built into the pipeline and the design, not bolted on after release. These blueprints cover how to catch leaks, model threats, protect APIs and produce audit evidence as part of normal engineering.

**Who this is for:** software engineers, DevSecOps teams and B2B SaaS founders preparing for enterprise buyers and audits.

## Start Here: Learning Path

1. **Shift-Left DevSecOps Pipeline Checklist** *(infographic, coming soon)*: IDE plugins, pre-commit hooks and CI/CD gates.
2. **Automated Secrets Scanning & SBOM in GitHub Actions** *(coming soon)*: block leaked keys on commit.
3. **Threat Modeling a SaaS Feature with STRIDE** *(coming soon)*: from data-flow diagram to security tickets.
4. **Securing REST & GraphQL APIs Against BOLA** *(coming soon)*: object-level authorization patterns.
5. **Tamper-Proof Audit Logs for SOC 2 & ISO 27001** *(coming soon)*: hash-chained event logging schemas.

## Core Principles

- **Shift left.** Catch issues at commit and build time, where fixes are cheap.
- **Model threats before writing code.** Turn each finding into a tracked ticket.
- **Check authorization on every object.** Never trust IDs supplied by the client.
- **Make evidence automatic.** Logs and pipeline records should satisfy auditors without manual work.
- **Verify the supply chain.** Know and sign what you ship.

## Related Pillars

- [AI Security](/ai-security/): securing LLM features inside your product
- [IAM](/iam/): authentication and token design
- [PAM](/pam/): privileged access to production and CI/CD

---

*All content is for educational and defensive security engineering purposes. Validate controls in staging before production.*
