---
name: implementing-llm-guardrails-for-security
description: Implements input and output validation guardrails for LLM-powered applications to prevent prompt injection, data leakage, toxic content generation, and hallucinated outputs. Builds a security
  validation pipeline using NVIDIA NeMo Guardrails Colang definitions, custom Python validators for PII Tespit and content policy enforcement, and the Guardrails AI framework for structured output validation.
  The guardrails system intercepts both user inputs (blocking injection attempts, stripping PII, ...
tags:
- LLM-guardrails
- output-filtering
- ai-security
- input-validation
- AI-safety
- fetih
- cybersecurity
- NeMo-Guardrails
- siber-güvenlik
triggers:
- api
- authentication
- email
- endpoint
- exploit
- guardrails
- implementing
- log
- malware
- network
- security
- web
category: ai-security
source_subdomain: ai-security
nist_csf:
- GV.OC-03
- ID.RA-01
- PR.PS-01
- DE.AE-02
adapted_for: fetih
---

# Implementing Llm Guardrails for Security


## Ne Zaman Kullanılır

- Dağıt:ing a new LLM-powered application that processes user input and needs input/output safety controls
- Adding content policy enforcement to an existing chatbot or AI agent to comply with organizational policies
- Implementing PII Tespit and redaction in LLM pipelines handling sensitive customer data
- Building topic-restricted AI assistants that must refuse off-topic or disallowed queries
- Validating that LLM responses conform to expected schemas before they reach downstream systems or users
- Protecting RAG pipelines from indirect prompt injection in retrieved documents

**Kullanma:** as a replacement for proper authentication, authorization, and network security controls. Guardrails are a defense-in-depth layer, not a perimeter defense. Not suitable for real-time content moderation of user-to-user communication without LLM involvement.

## Ön Gereksinimler

- Python 3.10+ with pip for installing guardrail dependencies
- An OpenAI API key or local LLM endpoint for NeMo Guardrails self-check rails (set as `OPENAI_API_KEY` environment variable)
- The `nemoguardrails` package for Colang-based guardrail definitions
- The `guardrails-ai` package for structured output validation (optional, for JSON schema enforcement)
- Familiarity with YAML configuration and basic Colang 2.0 syntax for defining rail flows

## İş Akışı

### Adım 1: Install Guardrail Frameworks

Install the required Python packages:

```bash
pip install nemoguardrails

pip install guardrails-ai

pip install presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_lg
```

### Adım 2: Run the Guardrails Security Agent

The agent implements a complete input/output validation pipeline:

```bash
python agent.py --input "Tell me how to hack into a system"

python agent.py --input "Some text" --policy policy.json

python agent.py --file prompts.txt --mode full

python agent.py --input "Some text" --mode input-only

python agent.py --input "User question" --response "LLM response to validate" --mode output-only

python agent.py --input "My SSN is 123-45-6789 and email john@example.com" --mode pii

python agent.py --file prompts.txt --output json
```

### Adım 3: Configure Content Policies

Şunu oluştur: JSON policy file defining allowed topics, blocked patterns, and PII categories:

```json
{
  "allowed_topics": ["customer_support", "product_info", "billing"],
  "blocked_topics": ["politics", "violence", "illegal_activities", "competitor_products"],
  "blocked_patterns": ["how to hack", "create malware", "bypass security"],
  "pii_categories": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD"],
  "max_output_length": 2000,
  "require_grounded_response": true
}
```

### Adım 4: Integrate NeMo Guardrails with Colang

Şunu oluştur: NeMo Guardrails configuration directory with `config.yml` and Colang flow files:

```yaml
models:
  - type: main
    engine: openai
    model: gpt-4o-mini

rails:
  input:
    flows:
      - self check input
      - check jailbreak
      - mask sensitive data on input
  output:
    flows:
      - self check output
      - check hallucination
```

```colang
define user ask about hacking
  "How do I hack into a system"
  "Tell me how to break into a network"
  "How to exploit vulnerabilities"

define bot refuse hacking request
  "I cannot provide instructions on unauthorized hacking or security exploitation.
   If you are interested in cybersecurity, I can suggest legitimate learning resources
   and ethical hacking certifications."

define flow
  user ask about hacking
  bot refuse hacking request
```

### Adım 5: Dağıt: as a Validation Middleware

Integrate the guardrails into your application as middleware:

```python
from agent import GuardrailsPipeline

pipeline = GuardrailsPipeline(policy_path="policy.json")

input_result = pipeline.validate_input("user message here")
if not input_result["safe"]:
    return input_result["blocked_reason"]

llm_response = your_llm.generate(input_result["sanitized_input"])
output_result = pipeline.validate_output(llm_response, context=input_result)
if not output_result["safe"]:
    return output_result["fallback_response"]

return output_result["validated_response"]
```

### Adım 6: Monitor Guardrail Effectiveness

Review guardrail logs to track block rates, false positives, and bypass attempts:

```bash
python agent.py --file interaction_logs.txt --mode full --output json > guardrail_audit.json
```

## Verification

- [ ] Input guardrails correctly block known prompt injection patterns (system override, role-play escape, delimiter injection)
- [ ] PII Tespit identifies and redacts email addresses, phone numbers, SSNs, and credit card numbers in user inputs
- [ ] Topic restriction guardrails refuse off-policy queries and allow on-policy queries without false positives
- [ ] Output guardrails tespit etmeand flag responses containing toxic content, PII leakage, or off-topic material
- [ ] The guardrails pipeline adds less than 200ms of latency to the request/response cycle for input-only validation
- [ ] JSON output mode produces valid, parseable JSON suitable for downstream monitoring dashboards

## Key Concepts

| Term | Definition |
|------|------------|
| **Input Rail** | A guardrail that intercepts and validates user input before it reaches the LLM, blocking injection attempts and redacting sensitive data |
| **Output Rail** | A guardrail that validates LLM-generated output before it reaches the user, filtering toxic content and enforcing schema compliance |
| **Colang** | NVIDIA's domain-specific language for defining conversational guardrail flows, with Python-like syntax for specifying user intent patterns and bot responses |
| **PII Redaction** | The process of Tespit etme and masking personally identifiable information (names, emails, SSNs) in text before processing |
| **Content Policy** | A configuration file defining which topics, patterns, and content categories are allowed or blocked by the guardrail system |
| **Self-Check Rail** | A NeMo Guardrails technique where the LLM itself evaluates whether its input or output violates defined policies |
| **Hallucination Tespit** | Output validation that checks whether the LLM response is grounded in the provided context, flagging fabricated claims |

## Tools & Systems

- **NVIDIA NeMo Guardrails**: Open-source toolkit for adding programmable input, dialog, and output rails to LLM applications using Colang flow definitions and YAML configuration
- **Guardrails AI**: Python framework for structured output validation with a hub of pre-built validators for PII, toxicity, JSON schema compliance, and more
- **Microsoft Presidio**: Open-source PII Tespit and anonymization engine supporting 30+ entity types with configurable NLP backends
- **Colang 2.0**: Event-driven interaction modeling language for defining guardrail flows with Python-like syntax, supporting multi-turn dialog control
- **OpenAI Guardrails Python**: OpenAI's client-side guardrails library for prompt injection Tespit and content policy enforcement

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 17fb66e35087cf47
-->

