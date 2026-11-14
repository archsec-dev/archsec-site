---
title: "AI Security"
linkTitle: "AI Security"
description: "Vendor-neutral AI security blueprints: defend RAG pipelines, secure MCP servers and AI agents, redact PII, and apply zero-trust to enterprise LLM systems."
weight: 1
cascade:
  type: docs
---

# AI Security

LLM applications blur the line between instructions and data, so classic input-validation habits are not enough. These blueprints show how to isolate untrusted content, constrain what agents can do, and prove it with code and tests.

**Who this is for:** security architects, DevSecOps engineers and developers shipping RAG, agents and LLM-backed APIs.

## Start Here: Learning Path

Work through the guides in order. Each one builds on the trust-boundary model from the first.

1. **OWASP Top 10 for LLMs & Agentic AI** *(infographic, coming soon)*: a visual attack map with code-level defenses.
2. **[Zero-Trust RAG: Defend Against Indirect Prompt Injection](/ai-security/defending-rag-indirect-prompt-injection/)**: context isolation, spotlighting, classifier guardrails and output sanitization.
3. **Securing MCP Servers & AI Agents** *(coming soon)*: least-privilege tool scopes and OAuth enforcement.
4. **PII Redaction Middleware for LLM APIs** *(coming soon)*: strip sensitive data before inference calls.
5. **Zero-Trust Architecture for Enterprise AI** *(coming soon)*: policy enforcement points and model audit logs.

## Latest Guide

{{< cards >}}
  {{< card link="/ai-security/defending-rag-indirect-prompt-injection/" title="Zero-Trust RAG vs. Indirect Prompt Injection" subtitle="How one poisoned email, PDF or web page can hijack a RAG pipeline, and the defense-in-depth architecture that stops it." >}}
{{< /cards >}}

## Core Principles

- **Separate the control plane from the data plane.** Retrieved text is data, never instructions.
- **Assume the model can be manipulated.** Design so a hijacked model still cannot do damage.
- **Enforce least privilege outside the model.** Scopes, allowlists and approvals belong in deterministic code.
- **Control egress as tightly as ingress.** Block exfiltration channels such as Markdown images and unvetted tool calls.
- **Log every allow and deny.** You cannot investigate what you did not record.

## Related Pillars

- [IAM](/iam/): identity and token controls for agents and services
- [PAM](/pam/): ephemeral access and non-human identity governance
- [Product Dev](/product-dev/): shift-left pipelines and API authorization

---

*All content is for educational and defensive security engineering purposes. Validate controls in staging before production.*
