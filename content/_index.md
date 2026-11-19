---
title: "archsec.dev | Zero-Trust Security Architectures & Reference Blueprints"
description: "Vendor-neutral threat models, trust-boundary diagrams, and code-verified blueprints for Agentic AI Security, MCP Gateways, IAM, PAM, and Secure Product Engineering."
draft: false
layout: hextra-home
---

{{< hextra/hero-badge link="/ai-security/securing-model-context-protocol-mcp/" >}}
  New Blueprint: Zero-Trust MCP Gateways &amp; Interactive Threat Lab
{{< /hextra/hero-badge >}}

{{< hextra/hero-headline >}}
  Deterministic security architectures for probabilistic &amp; cloud-native systems
{{< /hextra/hero-headline >}}

{{< hextra/hero-subtitle >}}
  Threat models, trust-boundary diagrams, and executable reference code for Security Architects and AI Engineers building RAG, autonomous agents, MCP integrations, and zero-trust identity.
{{< /hextra/hero-subtitle >}}

{{< hextra/hero-button text="Explore the AI Security Blueprints" link="/ai-security/" >}}

&nbsp;

## Four Architectural Pillars

{{< hextra/feature-grid cols="2" >}}
  {{< hextra/feature-card
    title="AI Security"
    subtitle="Contain indirect prompt injection, agent goal hijacking, memory poisoning, and MCP tool exploits with deterministic policy gates and runtime sandboxes."
    link="/ai-security/"
  >}}
  {{< hextra/feature-card
    title="IAM"
    subtitle="Architect phishing-resistant authentication and fine-grained authorization with OAuth 2.1, RFC 8693 token exchange, passkeys, and multi-tenant isolation."
    link="/iam/"
  >}}
  {{< hextra/feature-card
    title="PAM"
    subtitle="Eliminate standing credentials across human and non-human identities (NHI) using SPIFFE workloads, just-in-time elevation, and ephemeral short-lived tokens."
    link="/pam/"
  >}}
  {{< hextra/feature-card
    title="Product Dev"
    subtitle="Embed shift-left security into CI/CD with signed SBOM/AI-BOM provenance, canonical input validation, API gateway policies, and automated red-team harnesses."
    link="/product-dev/"
  >}}
{{< /hextra/feature-grid >}}

&nbsp;

## Featured Series: Zero-Trust Agentic AI Architecture

System prompts are guidance—not security boundaries. Work through our three-part engineering series covering every trust boundary from data ingestion to tool execution:

- **[Part 1: Zero-Trust RAG vs. Indirect Prompt Injection](/ai-security/defending-rag-indirect-prompt-injection/)** — Separate control and data planes using ingestion sanitization, cryptographic Spotlighting, Dual-LLM quarantine, and egress filtering.
- **[Part 2: Securing Autonomous AI Agents](/ai-security/securing-autonomous-ai-agents/)** — Defeat goal hijacking, cross-session memory poisoning, and Confused Deputy delegation with session taint tracking, RFC 8693 token exchange, and microVM sandboxes.
- **[Part 3: Securing the Model Context Protocol (MCP)](/ai-security/securing-model-context-protocol-mcp/)** — Stop tool poisoning, schema rug pulls, OAuth audience replay, and path traversal with a 4-layer MCP Security Gateway and interactive simulator.

[Start with the AI Security Learning Path →](/ai-security/)

---

*Independent engineering publication for defensive security architecture. Validate all policies, schemas, and controls in staging before production rollout.*