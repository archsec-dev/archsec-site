---
title: "AI Security"
linkTitle: "AI Security"
description: "Vendor-neutral AI security blueprints: defend RAG pipelines, secure autonomous AI agents, lock down MCP servers, and apply zero-trust to enterprise LLM systems."
weight: 1
draft: false
cascade:
  type: docs
---

LLM applications blur the line between instructions and data, so classic input-validation habits are not enough. These blueprints show how to isolate untrusted content, constrain what agents can do, and prove it with code and tests.

**Who this is for:** security architects, DevSecOps engineers, and developers shipping RAG pipelines, autonomous agents, and MCP-backed LLM systems.

## Start Here: Learning Path

Work through the guides in order. Each blueprint builds on the trust-boundary model from the previous layer.

1. **[OWASP Top 10 for LLMs & Agentic AI](/ai-security/owasp-llm-agentic-top10-infographic/)** *(infographic)*: a visual attack map with code-level defenses.
2. **[Zero-Trust RAG: Defend Against Indirect Prompt Injection](/ai-security/defending-rag-indirect-prompt-injection/)**: context isolation, cryptographic Spotlighting, classifier guardrails, and output sanitization.
3. **[Securing Autonomous AI Agents: Threat Modeling & Zero-Trust Controls](/ai-security/securing-autonomous-ai-agents/)**: session taint tracking, memory write-barriers, SPIFFE workload identities, RFC 8693 token exchange, and microVM sandboxes.
4. **[Securing the Model Context Protocol (MCP): Gateways, Auth & Tool Integrity](/ai-security/securing-model-context-protocol-mcp/)**: SHA-256 manifest pinning against rug pulls, OAuth 2.1 + RFC 8707 audience binding, canonical path guards, and an interactive gateway inspector.
5. **PII Redaction Middleware for LLM APIs** *(coming soon)*: strip sensitive data before inference calls.
6. **Zero-Trust Architecture for Enterprise AI** *(coming soon)*: policy enforcement points and dual-identity audit logs.

## Published Blueprints

{{< cards >}}
  {{< card link="/ai-security/defending-rag-indirect-prompt-injection/" title="1. Zero-Trust RAG vs. Indirect Prompt Injection" subtitle="How one poisoned email, PDF, or web page can hijack a RAG pipeline, and the 4-layer defense-in-depth architecture that stops it." >}}
  {{< card link="/ai-security/securing-autonomous-ai-agents/" title="2. Securing Autonomous AI Agents" subtitle="Threat modeling autonomous loops across identity, memory, and execution boundaries with RFC 8693 token exchange and deterministic policy gates." >}}
  {{< card link="/ai-security/securing-model-context-protocol-mcp/" title="3. Securing the Model Context Protocol (MCP)" subtitle="Defeating tool poisoning, schema rug pulls, OAuth audience replay, and path traversal with a Zero-Trust MCP Gateway + interactive lab." >}}
{{< /cards >}}

## Core Principles

- **Separate the control plane from the data plane.** Retrieved text and tool metadata are data, never instructions.
- **Assume the model can be manipulated.** Design so a hijacked model still cannot escalate privileges or exfiltrate data.
- **Enforce least privilege outside the model.** Scopes, allowlists, and approvals belong in deterministic code.
- **Control egress as tightly as ingress.** Block exfiltration channels such as Markdown images, unvetted tool calls, and tainted memory writes.
- **Log every allow and deny.** Attribute every action to both the human user (`sub`) and non-human agent workload (`act`).

## Related Pillars

- [IAM](/iam/): identity and token controls for agents and services
- [PAM](/pam/): ephemeral access and non-human identity governance
- [Product Dev](/product-dev/): shift-left pipelines and API authorization

---

*All content is for educational and defensive security engineering purposes. Validate controls in staging before production.*