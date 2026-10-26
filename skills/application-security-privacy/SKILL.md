# Skill: Application Security, Privacy, and Safe Telemetry Handling

## 1. Purpose
Ensure TraceHunt adheres to defensive security, data privacy, and ethical development constraints.

## 2. When to Use
During all development stages, code reviews, and threat modeling.

## 3. Prerequisites
Awareness of OWASP Top 10 and cybersecurity ethics guidelines.

## 4. Implementation Steps
1. Enforce strict input validation on all file uploads and query parameters.
2. Defend against stored XSS by escaping untrusted telemetry in all HTML/DOM outputs.
3. Prevent SQL injection by using SQLAlchemy parameterized queries exclusively.
4. Sanitize telemetry fixtures to exclude real-world PII, cleartext passwords, or proprietary tokens.
5. Strictly refuse to build offensive modules, credential dumping exploits, or backdoor capabilities.
6. Implement clear caveats that TraceHunt is an analytical prototype, not a production EDR.

## 5. Expected Outputs
Secure code patterns, input sanitizers, and security documentation in README.md.

## 6. Verification Criteria
Perform automated security checks and manual code review against injection vulnerabilities.

## 7. Common Failures & Troubleshooting
Using eval() or raw string SQL formatting; rendering raw HTML without escaping.

## 8. Safety & Ethical Considerations
Strictly adhere to harmless lab and analytical threat-hunting scope.

## 9. Documentation Updates
Document security architecture and limitations in docs/DECISIONS.md and README.md.
