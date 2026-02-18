const fs = require('fs-extra');
const path = require('path');

class MITREMapper {
  constructor() {
    this.techniques = this.loadTechniques();
    this.tactics = this.loadTactics();
    this.useCaseMappings = this.loadUseCaseMappings();
  }

  loadTechniques() {
    try {
      const techniquesPath = path.join(__dirname, '../config/mitre_techniques.json');
      return fs.readJsonSync(techniquesPath);
    } catch (error) {
      console.warn('MITRE techniques file not found, using defaults');
      return this.getDefaultTechniques();
    }
  }

  loadTactics() {
    try {
      const tacticsPath = path.join(__dirname, '../config/mitre_tactics.json');
      return fs.readJsonSync(tacticsPath);
    } catch (error) {
      console.warn('MITRE tactics file not found, using defaults');
      return this.getDefaultTactics();
    }
  }

  loadUseCaseMappings() {
    try {
      const mappingsPath = path.join(__dirname, '../config/use_case_mappings.json');
      return fs.readJsonSync(mappingsPath);
    } catch (error) {
      console.warn('Use case mappings file not found, using defaults');
      return this.getDefaultUseCaseMappings();
    }
  }

  getDefaultTechniques() {
    return {
      "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "tactics": ["Credential Access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Active Directory", "Authentication logs", "VPN logs"]
      },
      "T1110.003": {
        "id": "T1110.003",
        "name": "Password Spraying",
        "description": "Adversaries may use a single password against multiple accounts.",
        "tactics": ["Credential Access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Active Directory", "Authentication logs", "Cloud logs"]
      },
      "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
        "platforms": ["Windows", "Linux", "macOS", "Cloud"],
        "data_sources": ["Authentication logs", "Account management", "Cloud logs"]
      },
      "T1621": {
        "id": "T1621",
        "name": "Multi-Factor Authentication Request Generation",
        "description": "Adversaries may generate MFA requests to push notifications.",
        "tactics": ["Credential Access"],
        "platforms": ["Windows", "Linux", "macOS", "Cloud"],
        "data_sources": ["MFA logs", "Authentication logs"]
      },
      "T1098": {
        "id": "T1098",
        "name": "Account Manipulation",
        "description": "Adversaries may manipulate accounts to maintain access.",
        "tactics": ["Persistence", "Privilege Escalation"],
        "platforms": ["Windows", "Linux", "macOS", "Cloud"],
        "data_sources": ["Account management", "Audit logs", "Cloud logs"]
      },
      "T1204": {
        "id": "T1204",
        "name": "User Execution",
        "description": "Adversaries may rely on user-executed code.",
        "tactics": ["Execution"],
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Process monitoring", "File monitoring", "EDR logs"]
      },
      "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "description": "Adversaries may abuse PowerShell for execution.",
        "tactics": ["Execution"],
        "platforms": ["Windows"],
        "data_sources": ["Process monitoring", "Command logs", "PowerShell logs"]
      },
      "T1566.001": {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "description": "Adversaries may send emails with malicious attachments.",
        "tactics": ["Initial Access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Email logs", "Network traffic", "Antivirus"]
      },
      "T1566.002": {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "description": "Adversaries may send emails with malicious links.",
        "tactics": ["Initial Access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Email logs", "Web proxy", "DNS logs"]
      },
      "T1566.003": {
        "id": "T1566.003",
        "name": "Spearphishing via Service",
        "description": "Adversaries may use third-party services for phishing.",
        "tactics": ["Initial Access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Email logs", "Cloud service logs"]
      }
    };
  }

  getDefaultTactics() {
    return {
      "TA0001": {
        "id": "TA0001",
        "name": "Initial Access",
        "description": "The adversary is trying to get into your network."
      },
      "TA0002": {
        "id": "TA0002",
        "name": "Execution",
        "description": "The adversary is trying to run malicious code."
      },
      "TA0003": {
        "id": "TA0003",
        "name": "Persistence",
        "description": "The adversary is trying to maintain their foothold."
      },
      "TA0004": {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "description": "The adversary is trying to gain higher-level permissions."
      },
      "TA0005": {
        "id": "TA0005",
        "name": "Defense Evasion",
        "description": "The adversary is trying to avoid being detected."
      },
      "TA0006": {
        "id": "TA0006",
        "name": "Credential Access",
        "description": "The adversary is trying to steal account names and passwords."
      },
      "TA0007": {
        "id": "TA0007",
        "name": "Discovery",
        "description": "The adversary is trying to figure out your environment."
      },
      "TA0008": {
        "id": "TA0008",
        "name": "Lateral Movement",
        "description": "The adversary is trying to move through your environment."
      },
      "TA0009": {
        "id": "TA0009",
        "name": "Collection",
        "description": "The adversary is trying to gather data of interest to their goal."
      },
      "TA0010": {
        "id": "TA0010",
        "name": "Exfiltration",
        "description": "The adversary is trying to steal data."
      },
      "TA0011": {
        "id": "TA0011",
        "name": "Impact",
        "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data."
      }
    };
  }

  getDefaultUseCaseMappings() {
    return {
      "identity": {
        "brute_force": ["T1110"],
        "password_spray": ["T1110.003"],
        "impossible_travel": ["T1078"],
        "mfa_fatigue": ["T1621"],
        "privilege_escalation": ["T1098"],
        "account_manipulation": ["T1098"]
      },
      "malware": {
        "execution": ["T1204"],
        "powershell_abuse": ["T1059.001"],
        "file_execution": ["T1204"],
        "defense_evasion": ["T1059.001"]
      },
      "phishing": {
        "attachment": ["T1566.001"],
        "link": ["T1566.002"],
        "service": ["T1566.003"],
        "credential_harvesting": ["T1566.001", "T1566.002"]
      },
      "network": {
        "command_and_control": ["T1071"],
        "data_exfiltration": ["T1041"],
        "lateral_movement": ["T1021"],
        "reconnaissance": ["T1018"]
      }
    };
  }

  async getAllTechniques() {
    return this.techniques;
  }

  async getAllTactics() {
    return this.tactics;
  }

  getTechniqueById(techniqueId) {
    return this.techniques[techniqueId];
  }

  getTacticById(tacticId) {
    return this.tactics[tacticId];
  }

  getTechniquesByTactic(tacticId) {
    const techniques = [];
    Object.values(this.techniques).forEach(technique => {
      if (technique.tactics.includes(tacticId)) {
        techniques.push(technique);
      }
    });
    return techniques;
  }

  getTechniquesByCategory(category, subcategory = null) {
    const mappings = this.useCaseMappings[category];
    if (!mappings) return [];

    if (subcategory && mappings[subcategory]) {
      return mappings[subcategory].map(id => this.techniques[id]).filter(Boolean);
    }

    const allTechniqueIds = new Set();
    Object.values(mappings).forEach(techniqueIds => {
      techniqueIds.forEach(id => allTechniqueIds.add(id));
    });

    return Array.from(allTechniqueIds).map(id => this.techniques[id]).filter(Boolean);
  }

  mapUseCaseToTechniques(category, subcategory, description = '') {
    // First try direct mapping
    const techniques = this.getTechniquesByCategory(category, subcategory);
    
    if (techniques.length > 0) {
      return techniques;
    }

    // If no direct mapping, try to infer from description
    const inferredTechniques = this.inferTechniquesFromText(description);
    
    // Also try category-level mapping
    const categoryTechniques = this.getTechniquesByCategory(category);
    
    // Combine and deduplicate
    const allTechniques = [...techniques, ...inferredTechniques, ...categoryTechniques];
    const uniqueTechniques = allTechniques.filter((technique, index, self) => 
      index === self.findIndex(t => t.id === technique.id)
    );

    return uniqueTechniques;
  }

  inferTechniquesFromText(text) {
    if (!text || typeof text !== 'string') return [];

    const techniques = [];
    const lowerText = text.toLowerCase();

    // Keyword-based inference
    const keywordMappings = {
      'brute force': ['T1110'],
      'password spray': ['T1110.003'],
      'failed login': ['T1110'],
      'multiple failed': ['T1110'],
      'impossible travel': ['T1078'],
      'mfa': ['T1621'],
      'push notification': ['T1621'],
      'privilege escalation': ['T1098'],
      'admin rights': ['T1098'],
      'global admin': ['T1098'],
      'malware': ['T1204'],
      'powershell': ['T1059.001'],
      'encoded': ['T1059.001'],
      'downloadstring': ['T1059.001'],
      'phishing': ['T1566.001', 'T1566.002'],
      'email': ['T1566.001', 'T1566.002'],
      'attachment': ['T1566.001'],
      'link': ['T1566.002'],
      'suspicious login': ['T1078'],
      'credential': ['T1110', 'T1110.003']
    };

    Object.keys(keywordMappings).forEach(keyword => {
      if (lowerText.includes(keyword)) {
        keywordMappings[keyword].forEach(techniqueId => {
          const technique = this.getTechniqueById(techniqueId);
          if (technique && !techniques.find(t => t.id === technique.id)) {
            techniques.push(technique);
          }
        });
      }
    });

    // Extract explicit technique IDs from text
    const techniquePattern = /T\d{4}(?:\.\d{3})?/g;
    const explicitTechniques = text.match(techniquePattern) || [];
    
    explicitTechniques.forEach(techniqueId => {
      const technique = this.getTechniqueById(techniqueId);
      if (technique && !techniques.find(t => t.id === technique.id)) {
        techniques.push(technique);
      }
    });

    return techniques;
  }

  getTechniqueRecommendations(entityType, riskLevel = 'medium') {
    const recommendations = {
      'user': {
        'low': ['T1078'],
        'medium': ['T1110', 'T1078'],
        'high': ['T1110', 'T1110.003', 'T1078', 'T1621'],
        'critical': ['T1110', 'T1110.003', 'T1078', 'T1621', 'T1098']
      },
      'ip': {
        'low': ['T1078'],
        'medium': ['T1110', 'T1078'],
        'high': ['T1110', 'T1110.003', 'T1078'],
        'critical': ['T1110', 'T1110.003', 'T1078', 'T1621']
      },
      'file': {
        'low': ['T1204'],
        'medium': ['T1204', 'T1059.001'],
        'high': ['T1204', 'T1059.001', 'T1110'],
        'critical': ['T1204', 'T1059.001', 'T1110', 'T1078']
      },
      'url': {
        'low': ['T1566.002'],
        'medium': ['T1566.002', 'T1566.001'],
        'high': ['T1566.002', 'T1566.001', 'T1566.003'],
        'critical': ['T1566.002', 'T1566.001', 'T1566.003', 'T1110']
      }
    };

    const techniqueIds = recommendations[entityType]?.[riskLevel] || [];
    return techniqueIds.map(id => this.getTechniqueById(id)).filter(Boolean);
  }

  validateTechniqueIds(techniqueIds) {
    const valid = [];
    const invalid = [];

    techniqueIds.forEach(id => {
      if (this.getTechniqueById(id)) {
        valid.push(id);
      } else {
        invalid.push(id);
      }
    });

    return { valid, invalid };
  }

  getTechniqueChain(techniqueIds) {
    const techniques = techniqueIds.map(id => this.getTechniqueById(id)).filter(Boolean);
    
    // Group by tactics to identify potential attack chains
    const tacticGroups = {};
    techniques.forEach(technique => {
      technique.tactics.forEach(tactic => {
        if (!tacticGroups[tactic]) {
          tacticGroups[tactic] = [];
        }
        tacticGroups[tactic].push(technique);
      });
    });

    return {
      techniques,
      tacticGroups,
      attackChain: this.buildAttackChain(tacticGroups)
    };
  }

  buildAttackChain(tacticGroups) {
    const chain = [];
    
    // Typical attack progression
    const tacticOrder = [
      'TA0001', // Initial Access
      'TA0006', // Credential Access
      'TA0002', // Execution
      'TA0004', // Privilege Escalation
      'TA0003', // Persistence
      'TA0005', // Defense Evasion
      'TA0008', // Lateral Movement
      'TA0009', // Collection
      'TA0010', // Exfiltration
      'TA0011'  // Impact
    ];

    tacticOrder.forEach(tacticId => {
      if (tacticGroups[tacticId]) {
        chain.push({
          tactic: this.getTacticById(tacticId),
          techniques: tacticGroups[tacticId]
        });
      }
    });

    return chain;
  }
}

module.exports = MITREMapper;
