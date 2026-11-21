---
title: "PAM"
linkTitle: "PAM"
description: "Vendor-neutral PAM blueprints: zero standing privilege, break-glass workflows, ephemeral SSH and database certificates, non-human identity audits and Kubernetes access."
weight: 3
draft: = "false"
cascade:
  type: docs
---

# Privileged Access Management

Standing admin rights and long-lived keys turn one compromised account into a full breach. These blueprints show how to replace permanent privilege with just-in-time, audited and automatically expiring access.

**Who this is for:** platform and infrastructure engineers, SREs and security teams responsible for cloud, Kubernetes and production access.

## Start Here: Learning Path

1. **Standing Privilege vs. Zero Standing Privilege (ZSP)** *(infographic, coming soon)*: a blast-radius comparison diagram.
2. **Building a Break-Glass Emergency Admin Workflow** *(coming soon)*: hardware MFA and immutable alerts.
3. **Ephemeral SSH & Database Certificates** *(coming soon)*: eliminate static keys with an internal CA.
4. **Auditing Non-Human Identities (NHIs)** *(coming soon)*: discover and rotate orphaned service accounts.
5. **PAM Architecture for Kubernetes & Hybrid Cloud** *(coming soon)*: vaults, session proxies and JIT elevation.

## Core Principles

- **No standing privilege.** Grant access for a task, then revoke it automatically.
- **Prefer certificates and tokens over static keys.** Short TTLs limit the damage of theft.
- **Approve and record.** Elevated sessions need approval and a reviewable trail.
- **Treat machine identities like people.** Inventory, scope and rotate them.
- **Plan for emergencies.** Break-glass access must be rare, loud and fully logged.

## Related Pillars

- [AI Security](/ai-security/): least-privilege scopes for AI agents
- [IAM](/iam/): federation and token fundamentals
- [Product Dev](/product-dev/): hardened CI/CD and secrets scanning

---

*All content is for educational and defensive security engineering purposes. Validate controls in staging before production.*
