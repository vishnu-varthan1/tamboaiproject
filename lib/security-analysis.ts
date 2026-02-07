// Security Analysis Utilities
import {
  ThreatLevel,
  ThreatType,
  Threat,
  RiskScore,
  MitreAttack,
  Vulnerability,
  SecurityRecommendation,
  MessageSecurityAnalysis,
  THREAT_LEVELS,
  MITRE_TACTICS,
  THREAT_ICONS,
} from './security-types';

// Patterns for detecting security threats
const THREAT_PATTERNS: Record<ThreatType, RegExp[]> = {
  prompt_injection: [
    /ignore.*(previous|above|prior).*instructions/i,
    /forget.*(everything|all).*you.*(know|learned)/i,
    /you.*are.*(now|currently).*(a|an).*(different|new|new)/i,
    /act.*as.*(if|though).*(you|role)/i,
    /system.*prompt/i,
    /developer.*mode/i,
    /jailbreak/i,
    /bypass.*(restriction|limit|filter)/i,
    /\\u0001.*\\u0001/i,
  ],
  malware_indicators: [
    /powershell.*-enc/i,
    /base64.*encode.*shell/i,
    /msfconsole/i,
    /meterpreter/i,
    /reverse.*shell/i,
    /nc\s+-e/i,
    /\/bin\/bash.*-i.*>&.*&>/i,
  ],
  phishing: [
    /verify.*(your|account|identity)/i,
    /click.*(here|link).*(now|immediately)/i,
    /urgent.*(action|attention|response)/i,
    /suspended.*(account|service)/i,
    /confirm.*password/i,
    /update.*(payment|banking)/i,
  ],
  credential_leakage: [
    /(api|secret|access).*(key|token|credential)/i,
    /password.*=.*['"][^'"]+['"]/i,
    /Bearer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*/i,
    /sk-[A-Za-z0-9]{20,}/i,
    /github.*token/i,
    /aws.*key/i,
  ],
  insecure_code: [
    /eval\s*\(\s*(user|input|request)/i,
    /exec\s*\(\s*(user|input|request)/i,
    /exec\s*\(\s*['"].*\$/,
    /SELECT.*FROM.*WHERE.*=.*['"].*['"]/i,
    /string\.format.*user/i,
    /innerHTML/i,
    /dangerouslySetInnerHTML/i,
  ],
  data_exfiltration: [
    /curl.*-d.*http/i,
    /wget.*http/i,
    /fetch.*(external|remote).*data/i,
    /send.*(data|file).*(to|external)/i,
    /upload.*(sensitive|confidential)/i,
  ],
  social_engineering: [
    /pretend.*to.*(be|someone)/i,
    /act.*as.*(customer|support|admin)/i,
    /help.*me.*(steal|hack|exploit)/i,
    /can.*you.*(fake|forgery)/i,
  ],
  unauthorized_access: [
    /brute.*force/i,
    /sqlmap/i,
    /nikto/i,
    /nmap.*-sS/i,
    /hydra/i,
    /crack.*(password|hash)/i,
  ],
  sql_injection: [
    /['"]\s*OR\s+['"]\s*=\s*['"]/i,
    /UNION.*SELECT/i,
    /DROP.*TABLE/i,
    /DELETE.*FROM/i,
    /'\s*;\s*--/i,
    /execute.*(@@)/i,
  ],
  xss: [
    /<script>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe.*src.*javascript:/i,
    /document\.cookie/i,
    /alert\s*\(/i,
  ],
  csrf: [
    /CSRF.*token/i,
    /referer.*check/i,
    /same-site.*cookie/i,
  ],
  cryptographic_weakness: [
    /md5/i,
    /sha1/i,
    /DES/i,
    /ECB/i,
    /CBC.*without.*IV/i,
    /random\.rand.*(python|js)/i,
    /Math\.random/i,
  ],
};

// MITRE ATT&CK mappings
const MITRE_MAPPINGS: MitreAttack[] = [
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'initial_access',
    technique: 'T1190',
    description: 'Exploitation of web applications to gain initial access',
    detection: 'Monitor for unusual web traffic patterns, failed login attempts',
  },
  {
    id: 'T1204',
    name: 'User Execution',
    tactic: 'execution',
    technique: 'T1204',
    description: 'User execution of malicious code or links',
    detection: 'Endpoint detection, email security filters',
  },
  {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    tactic: 'persistence',
    technique: 'T1053',
    description: 'Creating scheduled tasks for persistent access',
    detection: 'Audit scheduled tasks, monitor task creation',
  },
  {
    id: 'T1068',
    name: 'Exploitation for Privilege Escalation',
    tactic: 'privilege_escalation',
    technique: 'T1068',
    description: 'Exploiting vulnerabilities to escalate privileges',
    detection: 'Patch management, privilege monitoring',
  },
  {
    id: 'T1070',
    name: 'Indicator Removal',
    tactic: 'defense_evasion',
    technique: 'T1070',
    description: 'Removing indicators of compromise',
    detection: 'File integrity monitoring, log analysis',
  },
  {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'credential_access',
    technique: 'T1110',
    description: 'Using brute force to obtain credentials',
    detection: 'Failed login monitoring, MFA enforcement',
  },
  {
    id: 'T1087',
    name: 'Account Discovery',
    tactic: 'discovery',
    technique: 'T1087',
    description: 'Discovering user accounts',
    detection: 'Audit account enumeration attempts',
  },
  {
    id: 'T1021',
    name: 'Remote Services',
    tactic: 'lateral_movement',
    technique: 'T1021',
    description: 'Using remote services to move laterally',
    detection: 'Network traffic analysis, access logs',
  },
  {
    id: 'T1213',
    name: 'Data from Information Repositories',
    tactic: 'collection',
    technique: 'T1213',
    description: 'Collecting data from information repositories',
    detection: 'Data access logging, DLP solutions',
  },
  {
    id: 'T1041',
    name: 'Exfiltration Over C2',
    tactic: 'exfiltration',
    technique: 'T1041',
    description: 'Exfiltrating data over command and control',
    detection: 'Network monitoring, C2 detection',
  },
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'impact',
    technique: 'T1486',
    description: 'Encrypting data for ransomware impact',
    detection: 'File encryption monitoring, backup verification',
  },
];

// Analyze content for threats
export function analyzeSecurity(content: string): Threat[] {
  const threats: Threat[] = [];
  const now = new Date();

  for (const [type, patterns] of Object.entries(THREAT_PATTERNS)) {
    for (let i = 0; i < patterns.length; i++) {
      const pattern = patterns[i];
      if (pattern.test(content)) {
        const severity = determineThreatSeverity(type as ThreatType);
        threats.push({
          id: `threat-${type}-${i}`,
          type: type as ThreatType,
          severity,
          title: getThreatTitle(type as ThreatType),
          description: getThreatDescription(type as ThreatType),
          confidence: calculateConfidence(content, pattern),
          mitigations: getThreatMitigations(type as ThreatType),
        });
      }
    }
  }

  return threats;
}

// Determine threat severity based on type
function determineThreatSeverity(type: ThreatType): ThreatLevel {
  const highSeverity: ThreatType[] = [
    'prompt_injection',
    'malware_indicators',
    'sql_injection',
    'data_exfiltration',
  ];
  const mediumSeverity: ThreatType[] = [
    'phishing',
    'credential_leakage',
    'unauthorized_access',
    'xss',
  ];
  const lowSeverity: ThreatType[] = [
    'insecure_code',
    'social_engineering',
    'csrf',
    'cryptographic_weakness',
  ];

  if (highSeverity.includes(type)) return 'critical';
  if (mediumSeverity.includes(type)) return 'high';
  return 'medium';
}

// Get threat title
function getThreatTitle(type: ThreatType): string {
  const titles: Record<ThreatType, string> = {
    prompt_injection: 'Prompt Injection Detected',
    malware_indicators: 'Malware Indicators Found',
    phishing: 'Phishing Pattern Detected',
    credential_leakage: 'Potential Credential Leakage',
    insecure_code: 'Insecure Code Pattern',
    data_exfiltration: 'Data Exfiltration Risk',
    social_engineering: 'Social Engineering Attempt',
    unauthorized_access: 'Unauthorized Access Pattern',
    sql_injection: 'SQL Injection Vulnerability',
    xss: 'Cross-Site Scripting (XSS) Risk',
    csrf: 'CSRF Vulnerability',
    cryptographic_weakness: 'Cryptographic Weakness',
  };
  return titles[type] || 'Security Concern';
}

// Get threat description
function getThreatDescription(type: ThreatType): string {
  const descriptions: Record<ThreatType, string> = {
    prompt_injection: 'The content attempts to manipulate AI behavior through malicious instructions',
    malware_indicators: 'Patterns associated with malware creation or execution detected',
    phishing: 'Content may be attempting to deceive users into revealing sensitive information',
    credential_leakage: 'Potential exposure of sensitive credentials or API keys',
    insecure_code: 'Code pattern may introduce security vulnerabilities',
    data_exfiltration: 'Content suggests potential data theft or unauthorized transfer',
    social_engineering: 'Attempt to manipulate users into performing actions or divulging information',
    unauthorized_access: 'Patterns suggesting attempts to gain unauthorized system access',
    sql_injection: 'Vulnerable database query pattern detected',
    xss: 'Cross-site scripting vulnerability pattern found',
    csrf: 'Cross-site request forgery vulnerability pattern',
    cryptographic_weakness: 'Weak cryptographic algorithm or implementation detected',
  };
  return descriptions[type] || 'Security concern identified';
}

// Calculate confidence score
function calculateConfidence(content: string, pattern: RegExp): number {
  const match = content.match(pattern);
  if (!match) return 0;
  return Math.min(95, 60 + (match[0].length / content.length) * 40);
}

// Get threat mitigations
function getThreatMitigations(type: ThreatType): string[] {
  const mitigations: Record<ThreatType, string[]> = {
    prompt_injection: [
      'Implement input validation and sanitization',
      'Use context-aware prompt filtering',
      'Enable secure mode for sensitive operations',
    ],
    malware_indicators: [
      'Block execution of suspicious scripts',
      'Use sandboxed environments',
      'Enable endpoint protection',
    ],
    phishing: [
      'Implement email authentication (SPF, DKIM, DMARC)',
      'Use anti-phishing filters',
      'Train users on phishing recognition',
    ],
    credential_leakage: [
      'Use secrets management systems',
      'Implement environment variable storage',
      'Enable API key rotation',
    ],
    insecure_code: [
      'Use parameterized queries',
      'Implement proper input validation',
      'Apply principle of least privilege',
    ],
    data_exfiltration: [
      'Implement DLP solutions',
      'Monitor network traffic',
      'Use data classification',
    ],
    social_engineering: [
      'Security awareness training',
      'Implement verification procedures',
      'Use multi-factor authentication',
    ],
    unauthorized_access: [
      'Implement rate limiting',
      'Use strong authentication',
      'Monitor for brute force attempts',
    ],
    sql_injection: [
      'Use parameterized queries',
      'Implement ORM libraries',
      'Apply input sanitization',
    ],
    xss: [
      'Implement Content Security Policy',
      'Escape user input',
      'Use frameworks with XSS protection',
    ],
    csrf: [
      'Implement anti-CSRF tokens',
      'Use SameSite cookie attribute',
      'Verify Origin/Referer headers',
    ],
    cryptographic_weakness: [
      'Use modern cryptographic algorithms (AES-256, SHA-256)',
      'Implement proper key management',
      'Use secure random number generators',
    ],
  };
  return mitigations[type] || ['Review and validate input', 'Implement security controls'];
}

// Calculate risk score
export function calculateRiskScore(content: string, threats: Threat[]): RiskScore {
  const promptInjectionScore = threats.filter(t => t.type === 'prompt_injection').length * 30;
  const dataPrivacyScore = threats.filter(t => 
    ['credential_leakage', 'data_exfiltration', 'phishing'].includes(t.type)
  ).length * 25;
  const codeSecurityScore = threats.filter(t => 
    ['insecure_code', 'sql_injection', 'xss', 'csrf', 'cryptographic_weakness'].includes(t.type)
  ).length * 20;
  const socialEngineeringScore = threats.filter(t => 
    ['social_engineering', 'phishing', 'unauthorized_access'].includes(t.type)
  ).length * 25;

  const overall = Math.min(100, 
    (promptInjectionScore + dataPrivacyScore + codeSecurityScore + socialEngineeringScore) / 4
  );

  return {
    overall: Math.round(overall),
    breakdown: {
      promptInjection: Math.min(100, promptInjectionScore),
      dataPrivacy: Math.min(100, dataPrivacyScore),
      codeSecurity: Math.min(100, codeSecurityScore),
      socialEngineering: Math.min(100, socialEngineeringScore),
    },
  };
}

// Get MITRE ATT&CK mappings for content
export function getMitreAttacks(content: string): MitreAttack[] {
  const attacks: MitreAttack[] = [];
  
  const contentLower = content.toLowerCase();
  
  for (const attack of MITRE_MAPPINGS) {
    const isRelevant = checkMitreRelevance(attack.id, contentLower);
    if (isRelevant) {
      attacks.push(attack);
    }
  }
  
  return attacks;
}

// Check MITRE ATT&CK relevance
function checkMitreRelevance(techniqueId: string, content: string): boolean {
  const relevanceMap: Record<string, string[]> = {
    'T1190': ['web app', 'web application', 'exploit', 'vulnerability'],
    'T1204': ['click', 'open', 'execute', 'run'],
    'T1053': ['schedule', 'cron', 'task', 'job'],
    'T1068': ['privilege', 'escalate', 'root', 'admin'],
    'T1070': ['delete', 'remove', 'clear', 'wipe'],
    'T1110': ['brute', 'force', 'guess', 'password'],
    'T1087': ['account', 'user', 'list', 'enum'],
    'T1021': ['remote', 'ssh', 'rdp', 'winrm'],
    'T1213': ['database', 'repo', 'repository', 'data'],
    'T1041': ['exfiltrate', 'steal', 'transfer', 'send'],
    'T1486': ['encrypt', 'ransom', 'lock', 'decrypt'],
  };

  const keywords = relevanceMap[techniqueId] || [];
  return keywords.some(keyword => content.includes(keyword));
}

// Generate vulnerability summary
export function getVulnerabilities(content: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  
  if (/sql|injection|select.*from/i.test(content)) {
    vulnerabilities.push({
      id: 'vuln-sql-1',
      cve: 'N/A',
      title: 'Potential SQL Injection',
      severity: 'high',
      cvss: 7.5,
      description: 'The content contains patterns that may indicate SQL injection vulnerabilities',
      affectedComponent: 'Database Query',
      remediation: 'Use parameterized queries or prepared statements',
      status: 'open',
    });
  }
  
  if (/eval|exec|innerhtml/i.test(content)) {
    vulnerabilities.push({
      id: 'vuln-code-1',
      title: 'Unsafe Code Execution Pattern',
      severity: 'medium',
      cvss: 6.3,
      description: 'Use of dynamic code execution functions detected',
      affectedComponent: 'Application Code',
      remediation: 'Avoid using eval(), exec(), or similar functions with user input',
      status: 'open',
    });
  }
  
  return vulnerabilities;
}

// Generate security recommendations
export function getRecommendations(threats: Threat[]): SecurityRecommendation[] {
  const recommendations: SecurityRecommendation[] = [];
  
  const hasPromptInjection = threats.some(t => t.type === 'prompt_injection');
  const hasCredentialLeakage = threats.some(t => t.type === 'credential_leakage');
  const hasCodeVulnerabilities = threats.some(t => 
    ['insecure_code', 'sql_injection', 'xss', 'csrf'].includes(t.type)
  );
  
  if (hasPromptInjection) {
    recommendations.push({
      id: 'rec-1',
      priority: 'critical',
      category: 'AI Safety',
      title: 'Implement Prompt Injection Protection',
      description: 'Enable strict mode to prevent prompt injection attacks',
      implementation: [
        'Activate secure mode in settings',
        'Implement input sanitization',
        'Use context isolation',
      ],
      estimatedEffort: 'low',
    });
  }
  
  if (hasCredentialLeakage) {
    recommendations.push({
      id: 'rec-2',
      priority: 'high',
      category: 'Credential Security',
      title: 'Secure Credential Handling',
      description: 'Review and secure any exposed credentials',
      implementation: [
        'Rotate any exposed credentials',
        'Use environment variables',
        'Implement secrets management',
      ],
      estimatedEffort: 'medium',
    });
  }
  
  if (hasCodeVulnerabilities) {
    recommendations.push({
      id: 'rec-3',
      priority: 'high',
      category: 'Code Security',
      title: 'Code Security Audit',
      description: 'Conduct security review of the affected code',
      implementation: [
        'Run static analysis tools',
        'Review input validation',
        'Implement secure coding practices',
      ],
      estimatedEffort: 'high',
    });
  }
  
  return recommendations;
}

// Main security analysis function
export function performSecurityAnalysis(content: string): MessageSecurityAnalysis {
  const threats = analyzeSecurity(content);
  const riskScore = calculateRiskScore(content, threats);
  const mitreAttacks = getMitreAttacks(content);
  const vulnerabilities = getVulnerabilities(content);
  const recommendations = getRecommendations(threats);
  
  const maxSeverity = threats.reduce((max, t) => {
    const severityScores = { low: 1, medium: 2, high: 3, critical: 4 };
    return severityScores[t.severity] > severityScores[max] ? t.severity : max;
  }, 'low' as ThreatLevel);
  
  return {
    threatLevel: maxSeverity,
    riskScore,
    threats,
    mitreAttacks,
    vulnerabilities,
    recommendations,
    isSafe: threats.length === 0,
    analysisTimestamp: new Date(),
  };
}

// Get threat level display info
export function getThreatLevelDisplay(level: ThreatLevel) {
  return THREAT_LEVELS[level];
}

// Get MITRE tactic display info
export function getMitreTacticDisplay(tactic: string) {
  return MITRE_TACTICS[tactic as keyof typeof MITRE_TACTICS] || { 
    color: 'var(--muted)', 
    icon: '📋' 
  };
}
