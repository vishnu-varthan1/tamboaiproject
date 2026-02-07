// ============ TAMBO AI SECURITY SCAN PROMPTS ============
// These prompts are used by the AI-powered security scanning engine

export const tamboScanPrompt = {
  system: `You are an elite Autonomous SOC (Security Operations Center) Engine with deep expertise in:
- Vulnerability assessment and CVE analysis
- MITRE ATT&CK framework mapping
- Compliance frameworks (SOC 2 Type II, ISO 27001, GDPR, PCI DSS)
- Threat intelligence and IOC correlation
- Incident response and forensics
- Risk assessment and prioritization

Your capabilities include:
1. Analyzing code repositories for security vulnerabilities
2. Identifying misconfigurations and security gaps
3. Mapping findings to MITRE ATT&CK techniques
4. Assessing compliance posture against industry standards
5. Generating actionable remediation recommendations
6. Correlating threats with known threat intelligence

You must:
- Use professional cybersecurity terminology
- Provide specific, actionable findings with CVSS scores
- Map all vulnerabilities to MITRE ATT&CK tactics/techniques
- Include confidence scores for all findings
- Prioritize critical and high-severity issues
- Provide remediation steps for each finding

When scanning, consider:
- Authentication and authorization mechanisms
- Input validation and output encoding
- Error handling and logging
- Dependencies and third-party libraries
- Network exposure and attack surface
- Data protection and encryption
- Session management
- Access control models`,

  user: `Perform a comprehensive AI-powered security scan with the following parameters:

**Scan Type:** {scanType}
**Target Scope:** {target}
**Analysis Options:**
- CVE Analysis: {includeCVE}
- MITRE ATT&CK Mapping: {includeMITRE}
- Compliance Assessment: {includeCompliance}

Please analyze the codebase and provide:

## 1. VULNERABILITY FINDINGS
For each vulnerability found, provide:
- ID (e.g., VULN-001)
- Type (e.g., command_injection, xss, auth_bypass)
- Severity (critical/high/medium/low)
- Title (short descriptive title)
- Detailed description
- CVSS score (if applicable)
- CVE identifier (if applicable)
- Affected component/file
- Confidence level (0-100)
- Exploitation status (proof_of_concept/exploited_in_wild/undetected)
- Remediation steps

## 2. THREAT INTELLIGENCE CORRELATION
- Identify any IOCs (Indicators of Compromise)
- Correlate with known threat feeds
- Map to APT groups if applicable
- Assess exploitation likelihood

## 3. MITRE ATT&CK MAPPING
Map all findings to MITRE ATT&CK techniques:
- Technique ID (e.g., T1190)
- Technique name
- Tactic (initial_access, execution, persistence, etc.)
- Detection difficulty
- Observed in current environment (yes/no)

## 4. COMPLIANCE IMPACT
Assess against:
- SOC 2 Type II (CC6.1, CC6.6, CC7.2, etc.)
- ISO 27001 (A.9.4.3, A.12.4.1, A.14.2.1, etc.)
- GDPR (Art. 32)
- PCI DSS (Req. 6.4, Req. 8.2)

For each failed control:
- Control ID
- Control title
- Gap description
- Risk level
- Remediation

## 5. RISK ASSESSMENT
- Overall risk score (0-100)
- Risk level (critical/high/medium/low)
- Blast radius assessment
- Business impact analysis

## 6. REMEDIATION ROADMAP
Categorize by timeline:
- Immediate (0-4 hours)
- Short-term (1-7 days)
- Long-term (1-4 weeks)

For each remediation:
- Priority number
- Action description
- Target system/component
- ETA
- Risk level of remediation

## 7. AI EXECUTIVE SUMMARY
Provide a concise SOC-style summary:
- Overall security posture
- Key findings
- Immediate actions required
- Strategic recommendations

Use professional cybersecurity language. Be specific about findings with exact file paths, CVSS scores, and actionable remediation steps.`,

  vulnerabilityAnalysis: `Analyze the following code for security vulnerabilities:

{code}

Provide:
1. Specific line numbers and affected code
2. Vulnerability type (injection, XSS, auth bypass, etc.)
3. CVSS score and severity
4. Exploitation scenario
5. Remediation code snippet`,

  complianceCheck: `Evaluate the following against {framework} requirements:

{code}

Identify:
1. Control gaps
2. Non-compliant areas
3. Required changes
4. Priority level`,

  threatModeling: `Perform threat modeling analysis:

Asset: {asset}
Trust Boundary: {boundary}
Data Flow: {flow}

Identify:
1. Threat actors
2. Attack vectors
3. Risk level
4. Mitigation strategies`
};

// ============ TAMBO AI CUSTOM TOOLS ============
// These tools can be registered with Tambo for enhanced scanning

export const securityScanTools = [
  {
    name: "vulnerability_scan",
    description: "Perform AI-powered vulnerability scan on code or infrastructure",
    parameters: {
      type: "object",
      properties: {
        scanType: {
          type: "string",
          enum: ["vulnerability", "compliance", "full"],
          description: "Type of security scan to perform"
        },
        target: {
          type: "string",
          description: "Target scope (file path, URL, or 'full-scope')"
        },
        options: {
          type: "object",
          properties: {
            includeCVE: { type: "boolean" },
            includeMITRE: { type: "boolean" },
            includeCompliance: { type: "boolean" }
          }
        }
      },
      required: ["scanType"]
    }
  },
  {
    name: "threat_intel_lookup",
    description: "Query threat intelligence for IOCs",
    parameters: {
      type: "object",
      properties: {
        indicator: {
          type: "string",
          description: "IOC to query (IP, domain, hash, CVE)"
        },
        sources: {
          type: "array",
          items: { type: "string" },
          description: "Threat intel sources to query"
        }
      },
      required: ["indicator"]
    }
  },
  {
    name: "mitre_mapping",
    description: "Map security findings to MITRE ATT&CK framework",
    parameters: {
      type: "object",
      properties: {
        vulnerabilityType: {
          type: "string",
          description: "Type of vulnerability or attack pattern"
        },
        attackVector: {
          type: "string",
          description: "How the attack is delivered/executed"
        }
      },
      required: ["vulnerabilityType"]
    }
  },
  {
    name: "compliance_assessment",
    description: "Assess security posture against compliance frameworks",
    parameters: {
      type: "object",
      properties: {
        framework: {
          type: "string",
          enum: ["SOC2", "ISO27001", "GDPR", "PCI DSS", "all"],
          description: "Compliance framework to assess"
        },
        scope: {
          type: "string",
          description: "Scope of assessment"
        }
      },
      required: ["framework"]
    }
  }
];
