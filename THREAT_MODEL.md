# Threat model (template: edit for your own target)

**Asset:** internal API key (canary), customer PII (email), integrity of the bot's behaviour.
**Attacker:** anonymous end user, or an author of content the bot retrieves (email, ticket, web page, review).
**Trust boundaries:** system prompt (trusted) | user input, retrieved documents, client-supplied history (untrusted).
**Attacker goals measured:** leak the secret, make the bot emit attacker-chosen text, exfiltrate data via URLs/images.
**Out of scope:** model weights extraction, training-data poisoning, jailbreaks to harmful content, DoS, infrastructure.

**Key design lesson the results should support:** prompt hardening and filters lower risk but do not remove it.
Real mitigations are architectural: keep secrets out of prompts, enforce authorization outside the model, never
render untrusted URLs/images automatically, and treat model output as untrusted input to the rest of the system.
