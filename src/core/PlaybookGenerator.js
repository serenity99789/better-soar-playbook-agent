const { v4: uuidv4 } = require('uuid');
const SmartInputProcessor = require('./SmartInputProcessor');
const MITREMapper = require('./MITREMapper');
const QueryGenerator = require('./QueryGenerator');
const FieldMappingEngine = require('./FieldMappingEngine');
const RiskCalculator = require('./RiskCalculator');

class PlaybookGenerator {
  constructor() {
    this.smartInputProcessor = new SmartInputProcessor();
    this.mitreMapper = new MITREMapper();
    this.queryGenerator = new QueryGenerator();
    this.fieldMapper = new FieldMappingEngine();
    this.riskCalculator = new RiskCalculator();
    this.useCaseTemplates = this.loadUseCaseTemplates();
  }

  async generateFromText(text, platform, options = {}) {
    try {
      // Process input with smart processing
      const processedInput = await this.smartInputProcessor.processInput(text, 'text', options);
      
      // Generate use case from processed input
      const useCase = await this.createUseCase(processedInput, options);
      
      // Generate platform-specific queries
      const queries = this.generateQueries(useCase, platform, options);
      
      // Generate response actions
      const actions = this.queryGenerator.generateResponseActions(useCase, platform);
      
      // Create complete playbook
      const playbook = this.assemblePlaybook(useCase, queries, actions, platform, options);
      
      return {
        success: true,
        playbook: playbook,
        metadata: {
          generated_at: new Date().toISOString(),
          platform: platform,
          input_type: 'text',
          use_case_id: useCase.use_case_metadata.use_case_id,
          smart_processing: {
            llm_enhanced: processedInput.llm_enhanced,
            llm_provider: processedInput.llm_provider,
            llm_confidence: processedInput.llm_confidence,
            llm_insights: processedInput.llm_insights
          }
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  async generateFromFile(filePath, platform, options = {}) {
    try {
      // Process input file with smart processing
      const processedInput = await this.smartInputProcessor.processInput(filePath, 'file', options);
      
      // Generate use case from processed input
      const useCase = await this.createUseCase(processedInput, options);
      
      // Generate platform-specific queries
      const queries = this.generateQueries(useCase, platform, options);
      
      // Generate response actions
      const actions = this.queryGenerator.generateResponseActions(useCase, platform);
      
      // Create complete playbook
      const playbook = this.assemblePlaybook(useCase, queries, actions, platform, options);
      
      return {
        success: true,
        playbook: playbook,
        metadata: {
          generated_at: new Date().toISOString(),
          platform: platform,
          input_type: 'file',
          file_path: filePath,
          use_case_id: useCase.use_case_metadata.use_case_id,
          smart_processing: {
            llm_enhanced: processedInput.llm_enhanced,
            llm_provider: processedInput.llm_provider,
            llm_confidence: processedInput.llm_confidence,
            llm_insights: processedInput.llm_insights
          }
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  async createUseCase(processedInput, options = {}) {
    const { normalizedData, extractedFields } = processedInput;
    const { category, subcategory, severity } = options;

    // Generate use case ID
    const useCaseId = this.generateUseCaseId(category, subcategory);
    
    // Map to MITRE techniques
    const mitreTechniques = this.mitreMapper.mapUseCaseToTechniques(
      category, 
      subcategory, 
      processedInput.content
    );

    // Create use case structure
    const useCase = {
      schema_version: "1.0",
      use_case_metadata: {
        use_case_id: useCaseId,
        use_case_name: this.generateUseCaseName(normalizedData, category, subcategory),
        description: normalizedData.description || processedInput.content.substring(0, 200),
        category: category || this.inferCategory(normalizedData, extractedFields),
        sub_category: subcategory || this.inferSubcategory(normalizedData, extractedFields),
        mitre_techniques: mitreTechniques.map(t => t.id),
        created_by: "AI Playbook Generator",
        last_updated: new Date().toISOString().split('T')[0],
        status: "Draft"
      },

      detection_logic: this.createDetectionLogic(normalizedData, extractedFields, options),

      normalized_fields: {
        username: normalizedData.username || "string",
        source_ip: normalizedData.source_ip || "ip",
        destination_ip: normalizedData.destination_ip || "ip",
        hostname: normalizedData.hostname || "string",
        file_hash: normalizedData.file_hash || "string",
        url: normalizedData.url || "string",
        timestamp: normalizedData.timestamp || "datetime",
        entity_type: normalizedData.entity_type || "string"
      },

      platform_mapping: this.createPlatformMapping(normalizedData),

      risk_model: this.createRiskModel(severity, mitreTechniques, normalizedData),

      response_orchestration: this.createResponseOrchestration(normalizedData, mitreTechniques),

      asset_context: {
        asset_criticality_aware: true,
        identity_type: this.inferIdentityType(normalizedData)
      }
    };

    return useCase;
  }

  generateUseCaseId(category, subcategory) {
    const categoryCode = category ? category.toUpperCase().substring(0, 3) : 'GEN';
    const subcategoryCode = subcategory ? subcategory.toUpperCase().substring(0, 3) : 'UNK';
    const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    return `UC-${categoryCode}-${random}`;
  }

  generateUseCaseName(normalizedData, category, subcategory) {
    const entityType = normalizedData.entity_type || 'activity';
    const baseNames = {
      'user': {
        'brute_force': 'Multiple Failed Logins Followed by Success',
        'password_spray': 'Password Spray Attack Detected',
        'impossible_travel': 'Impossible Travel Login Detected',
        'mfa_fatigue': 'MFA Fatigue Attack Detected',
        'privilege_escalation': 'Privileged Role Assignment Detected'
      },
      'ip': {
        'brute_force': 'Brute Force Attack from Source IP',
        'password_spray': 'Password Spray from Source IP',
        'malicious_activity': 'Malicious Activity from Source IP'
      },
      'file': {
        'malware': 'Known Malware Hash Detected',
        'suspicious_execution': 'Suspicious File Execution Detected'
      },
      'url': {
        'phishing': 'Malicious URL Access Detected',
        'suspicious_access': 'Suspicious URL Access Pattern'
      }
    };

    if (category && subcategory && baseNames[entityType] && baseNames[entityType][subcategory]) {
      return baseNames[entityType][subcategory];
    }

    return `Suspicious ${entityType} Activity Detected`;
  }

  createDetectionLogic(normalizedData, extractedFields, options) {
    const entityType = normalizedData.entity_type;
    const conditions = [];

    // Base condition on entity type
    switch (entityType) {
      case 'user':
        conditions.push({
          field: 'username',
          operator: 'exists',
          value: true
        });
        break;
      case 'ip':
        conditions.push({
          field: 'source_ip',
          operator: 'exists',
          value: true
        });
        break;
      case 'file':
        conditions.push({
          field: 'file_hash',
          operator: 'exists',
          value: true
        });
        break;
      case 'url':
        conditions.push({
          field: 'url',
          operator: 'exists',
          value: true
        });
        break;
    }

    // Add aggregation if multiple events
    if (options.threshold) {
      conditions.push({
        aggregation: 'count',
        threshold: options.threshold,
        time_window: options.timeWindow || '5m'
      });
    }

    // Add sequence detection if specified
    if (options.sequenceDetection) {
      conditions.push({
        sequence_followed_by: options.sequenceFollowedBy || 'success',
        within: options.sequenceWithin || '2m'
      });
    }

    return {
      primary_entity: entityType,
      secondary_entity: this.getSecondaryEntity(entityType, normalizedData),
      event_type: this.inferEventType(entityType, options),
      conditions: conditions
    };
  }

  createPlatformMapping(normalizedData) {
    return {
      splunk_cim: this.fieldMapper.mapFields(normalizedData, 'splunk'),
      google_udm: this.fieldMapper.mapFields(normalizedData, 'google')
    };
  }

  createRiskModel(severity, mitreTechniques, normalizedData) {
    const baseSeverity = severity || this.calculateBaseSeverity(mitreTechniques, normalizedData);
    const riskScore = this.riskCalculator.calculateRiskScore(baseSeverity, mitreTechniques, normalizedData);
    
    return {
      base_severity: baseSeverity,
      risk_score: riskScore,
      risk_adjustments: this.riskCalculator.getRiskAdjustments(mitreTechniques, normalizedData)
    };
  }

  createResponseOrchestration(normalizedData, mitreTechniques) {
    const entityType = normalizedData.entity_type;
    const automatedActions = this.getDefaultActions(entityType);
    const approvalRequired = this.requiresApproval(entityType, mitreTechniques);

    return {
      automated_actions: automatedActions,
      conditional_actions: this.getConditionalActions(entityType, mitreTechniques),
      approval_required: approvalRequired,
      notify: this.getNotificationRecipients(entityType, mitreTechniques)
    };
  }

  generateQueries(useCase, platform, options) {
    const queries = [];
    
    // Generate primary detection query
    const primaryQuery = this.queryGenerator.generateQuery(useCase, platform, options);
    queries.push(primaryQuery);

    // Generate enrichment queries if needed
    const enrichmentQueries = this.generateEnrichmentQueries(useCase, platform);
    queries.push(...enrichmentQueries);

    return queries;
  }

  generateEnrichmentQueries(useCase, platform) {
    const queries = [];
    const { normalized_fields } = useCase;

    // IP enrichment query
    if (normalized_fields.source_ip && normalized_fields.source_ip !== "ip") {
      const ipQuery = {
        type: 'enrichment',
        name: 'IP Reputation Lookup',
        platform: platform,
        query: this.generateIPEnrichmentQuery(normalized_fields.source_ip, platform),
        description: 'Lookup IP reputation and geolocation data'
      };
      queries.push(ipQuery);
    }

    // Hash enrichment query
    if (normalized_fields.file_hash && normalized_fields.file_hash !== "string") {
      const hashQuery = {
        type: 'enrichment',
        name: 'File Hash Reputation',
        platform: platform,
        query: this.generateHashEnrichmentQuery(normalized_fields.file_hash, platform),
        description: 'Lookup file hash in threat intelligence databases'
      };
      queries.push(hashQuery);
    }

    return queries;
  }

  generateIPEnrichmentQuery(ipField, platform) {
    switch (platform.toLowerCase()) {
      case 'splunk':
        return `| splunksearch index=threatintel ip=${ipField} | stats count by ip, reputation, country`;
      case 'chronicle':
        return `events | where principal.ip = ${ipField} | group_by principal.ip, principal.geo_asn.name, principal.geo_region.name`;
      default:
        return `# IP enrichment query for ${ipField}`;
    }
  }

  generateHashEnrichmentQuery(hashField, platform) {
    switch (platform.toLowerCase()) {
      case 'splunk':
        return `| splunksearch index=threatintel hash=${hashField} | stats count by hash, signature, severity`;
      case 'chronicle':
        return `events | where target.file.sha256 = ${hashField} | group_by target.file.sha256, target.process.command_line`;
      default:
        return `# Hash enrichment query for ${hashField}`;
    }
  }

  assemblePlaybook(useCase, queries, actions, platform, options) {
    return {
      playbook_id: uuidv4(),
      playbook_name: useCase.use_case_metadata.use_case_name,
      playbook_version: "1.0",
      platform: platform,
      created_at: new Date().toISOString(),
      use_case: useCase,
      queries: queries,
      actions: actions,
      validation: this.validatePlaybook(useCase),
      metadata: {
        generated_by: "AI Playbook Generator",
        version: "1.0.0",
        tags: this.generateTags(useCase, platform)
      }
    };
  }

  validatePlaybook(playbook) {
    const validation = {
      valid: true,
      errors: [],
      warnings: []
    };

    // Validate required fields
    if (!playbook.use_case_metadata.use_case_id) {
      validation.errors.push('Use case ID is required');
      validation.valid = false;
    }

    if (!playbook.detection_logic.conditions || playbook.detection_logic.conditions.length === 0) {
      validation.errors.push('Detection logic must have at least one condition');
      validation.valid = false;
    }

    if (!playbook.mitre_techniques || playbook.mitre_techniques.length === 0) {
      validation.warnings.push('No MITRE techniques mapped');
    }

    // Validate platform mappings
    if (!playbook.platform_mapping) {
      validation.errors.push('Platform mapping is required');
      validation.valid = false;
    }

    return validation;
  }

  getUseCaseTemplates() {
    return this.useCaseTemplates;
  }

  loadUseCaseTemplates() {
    return {
      identity: {
        brute_force: {
          category: "Identity",
          subcategory: "Brute Force",
          description: "Detect brute force attacks against user accounts",
          mitre_techniques: ["T1110"],
          data_sources: ["Authentication logs", "Active Directory"],
          severity: "High"
        },
        password_spray: {
          category: "Identity",
          subcategory: "Credential Abuse",
          description: "Detect password spray attacks",
          mitre_techniques: ["T1110.003"],
          data_sources: ["Authentication logs", "Cloud logs"],
          severity: "High"
        },
        impossible_travel: {
          category: "Identity",
          subcategory: "Suspicious Login",
          description: "Detect impossible travel scenarios",
          mitre_techniques: ["T1078"],
          data_sources: ["Authentication logs", "GeoIP data"],
          severity: "High"
        }
      },
      malware: {
        execution: {
          category: "Malware",
          subcategory: "Execution",
          description: "Detect malware execution",
          mitre_techniques: ["T1204"],
          data_sources: ["EDR logs", "Process monitoring"],
          severity: "High"
        },
        powershell_abuse: {
          category: "Malware",
          subcategory: "Defense Evasion",
          description: "Detect suspicious PowerShell activity",
          mitre_techniques: ["T1059.001"],
          data_sources: ["PowerShell logs", "Process monitoring"],
          severity: "High"
        }
      },
      phishing: {
        email_attachment: {
          category: "Phishing",
          subcategory: "Email Attack",
          description: "Detect phishing emails with malicious attachments",
          mitre_techniques: ["T1566.001"],
          data_sources: ["Email logs", "Antivirus"],
          severity: "Medium"
        },
        malicious_link: {
          category: "Phishing",
          subcategory: "Email Attack",
          description: "Detect phishing emails with malicious links",
          mitre_techniques: ["T1566.002"],
          data_sources: ["Email logs", "Web proxy"],
          severity: "Medium"
        }
      }
    };
  }

  // Helper methods
  inferCategory(normalizedData, extractedFields) {
    if (normalizedData.entity_type === 'user' || normalizedData.username) {
      return 'Identity';
    } else if (normalizedData.entity_type === 'file' || normalizedData.file_hash) {
      return 'Malware';
    } else if (extractedFields.email || extractedFields.url) {
      return 'Phishing';
    }
    return 'Unknown';
  }

  inferSubcategory(normalizedData, extractedFields) {
    const text = JSON.stringify(normalizedData).toLowerCase();
    
    if (text.includes('brute') || text.includes('failed')) return 'Brute Force';
    if (text.includes('password') || text.includes('spray')) return 'Credential Abuse';
    if (text.includes('travel') || text.includes('geo')) return 'Suspicious Login';
    if (text.includes('mfa') || text.includes('push')) return 'MFA Abuse';
    if (text.includes('privilege') || text.includes('admin')) return 'Privilege Escalation';
    if (text.includes('malware') || text.includes('execution')) return 'Execution';
    if (text.includes('powershell') || text.includes('encoded')) return 'Defense Evasion';
    if (text.includes('email') || text.includes('attachment')) return 'Email Attack';
    
    return 'Unknown';
  }

  inferEventType(entityType, options) {
    const eventTypeMap = {
      'user': 'authentication',
      'ip': 'network',
      'file': 'process',
      'url': 'web'
    };
    
    return options.eventType || eventTypeMap[entityType] || 'unknown';
  }

  getSecondaryEntity(entityType, normalizedData) {
    switch (entityType) {
      case 'user':
        return normalizedData.source_ip ? 'source_ip' : null;
      case 'ip':
        return normalizedData.username ? 'username' : null;
      default:
        return null;
    }
  }

  calculateBaseSeverity(mitreTechniques, normalizedData) {
    if (mitreTechniques.some(t => t.id === 'T1098')) return 'Critical';
    if (mitreTechniques.some(t => t.id === 'T1110' || t.id === 'T1110.003')) return 'High';
    if (mitreTechniques.some(t => t.id.startsWith('T1566'))) return 'Medium';
    return 'Low';
  }

  getDefaultActions(entityType) {
    const actionMap = {
      'user': ['reset_password', 'revoke_sessions'],
      'ip': ['block_source_ip'],
      'file': ['isolate_host', 'block_hash'],
      'url': ['block_url']
    };
    
    return actionMap[entityType] || ['escalate_to_analyst'];
  }

  getConditionalActions(entityType, mitreTechniques) {
    const actions = [];
    
    if (entityType === 'user' && mitreTechniques.some(t => t.id === 'T1098')) {
      actions.push({
        if: 'privileged_account',
        then: 'approval_workflow + alert Security'
      });
    }
    
    if (entityType === 'file' && mitreTechniques.some(t => t.id === 'T1204')) {
      actions.push({
        if: 'server_host',
        then: 'isolate_host + collect_forensic_logs'
      });
    }
    
    return actions;
  }

  requiresApproval(entityType, mitreTechniques) {
    if (entityType === 'user' && mitreTechniques.some(t => t.id === 'T1098')) return true;
    if (entityType === 'file' && mitreTechniques.some(t => t.id === 'T1204')) return true;
    return false;
  }

  getNotificationRecipients(entityType, mitreTechniques) {
    const recipients = ['SOC'];
    
    if (entityType === 'user') recipients.push('Identity Team');
    if (mitreTechniques.some(t => t.id === 'T1204')) recipients.push('Endpoint Team');
    
    return recipients;
  }

  inferIdentityType(normalizedData) {
    if (normalizedData.username && normalizedData.username.includes('@')) {
      return ['employee'];
    }
    return ['employee', 'service_account'];
  }

  generateTags(useCase, platform) {
    const tags = [platform, useCase.use_case_metadata.category.toLowerCase()];
    
    if (useCase.use_case_metadata.sub_category) {
      tags.push(useCase.use_case_metadata.sub_category.toLowerCase().replace(' ', '_'));
    }
    
    useCase.mitre_techniques.forEach(technique => {
      tags.push(technique.toLowerCase());
    });
    
    return tags;
  }

  exportPlaybook(playbook, format = 'json') {
    switch (format.toLowerCase()) {
      case 'json':
        return JSON.stringify(playbook, null, 2);
      case 'yaml':
        // Simple YAML conversion (would normally use a YAML library)
        return this.convertToYAML(playbook);
      case 'markdown':
        return this.convertToMarkdown(playbook);
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  convertToYAML(obj) {
    // Simple YAML conversion - in production, use a proper YAML library
    return JSON.stringify(obj, null, 2)
      .replace(/"/g, '')
      .replace(/,/g, '')
      .replace(/\{/g, '')
      .replace(/\}/g, '');
  }

  convertToMarkdown(playbook) {
    let markdown = `# ${playbook.playbook_name}\n\n`;
    markdown += `**Platform:** ${playbook.platform}\n`;
    markdown += `**Created:** ${playbook.created_at}\n\n`;
    
    markdown += `## Use Case Details\n\n`;
    markdown += `**Category:** ${playbook.use_case.use_case_metadata.category}\n`;
    markdown += `**Sub-Category:** ${playbook.use_case.use_case_metadata.sub_category}\n`;
    markdown += `**MITRE Techniques:** ${playbook.use_case.mitre_techniques.join(', ')}\n\n`;
    
    markdown += `## Detection Logic\n\n`;
    playbook.use_case.detection_logic.conditions.forEach(condition => {
      markdown += `- ${condition.field} ${condition.operator} ${condition.value}\n`;
    });
    
    markdown += `\n## Queries\n\n`;
    playbook.queries.forEach(query => {
      markdown += `### ${query.name || 'Detection Query'}\n`;
      markdown += `\`\`\`\n${query.query}\n\`\`\`\n\n`;
    });
    
    markdown += `## Response Actions\n\n`;
    playbook.actions.actions.forEach(action => {
      markdown += `- **${action.name}:** ${action.description}\n`;
    });
    
    return markdown;
  }
}

module.exports = PlaybookGenerator;
