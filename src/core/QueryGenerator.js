const FieldMappingEngine = require('./FieldMappingEngine');

class QueryGenerator {
  constructor() {
    this.fieldMapper = new FieldMappingEngine();
  }

  generateQuery(useCase, platform, options = {}) {
    switch (platform.toLowerCase()) {
      case 'splunk':
        return this.generateSplunkQuery(useCase, options);
      case 'google':
      case 'chronicle':
        return this.generateChronicleQuery(useCase, options);
      default:
        throw new Error(`Unsupported platform: ${platform}`);
    }
  }

  generateSplunkQuery(useCase, options = {}) {
    const { detection_logic, normalized_fields, platform_mapping } = useCase;
    const { data_model } = options;
    
    if (!data_model) {
      throw new Error('Data model is required for Splunk query generation');
    }

    const mappedFields = this.fieldMapper.mapFields(normalized_fields, 'splunk', data_model);
    const query = this.buildSplunkQuery(detection_logic, mappedFields, data_model);
    
    return {
      platform: 'splunk',
      query: query.query,
      parameters: query.parameters,
      data_model: data_model,
      description: query.description
    };
  }

  generateChronicleQuery(useCase, options = {}) {
    const { detection_logic, normalized_fields } = useCase;
    
    const mappedFields = this.fieldMapper.mapFields(normalized_fields, 'google');
    const query = this.buildChronicleQuery(detection_logic, mappedFields);
    
    return {
      platform: 'chronicle',
      query: query.query,
      parameters: query.parameters,
      description: query.description
    };
  }

  buildSplunkQuery(detectionLogic, mappedFields, dataModel) {
    const { conditions, primary_entity, secondary_entity } = detectionLogic;
    let query = `| tstats summariesonly=true count from datamodel=${dataModel}`;
    let whereClause = '';
    let groupBy = [];

    // Build WHERE clause from conditions
    conditions.forEach(condition => {
      if (condition.field && condition.operator && condition.value) {
        const mappedField = mappedFields[condition.field] || condition.field;
        
        if (whereClause) whereClause += ' AND ';
        
        switch (condition.operator) {
          case 'equals':
            whereClause += `${dataModel}.${mappedField}="${condition.value}"`;
            break;
          case 'not_equals':
            whereClause += `${dataModel}.${mappedField}!="${condition.value}"`;
            break;
          case 'contains':
            whereClause += `${dataModel}.${mappedField}="*${condition.value}*"`;
            break;
          case 'regex':
            whereClause += `${dataModel}.${mappedField}=regex("${condition.value}")`;
            break;
          default:
            whereClause += `${dataModel}.${mappedField}="${condition.value}"`;
        }
      }

      // Handle aggregations
      if (condition.aggregation && condition.threshold) {
        if (whereClause) whereClause += ' AND ';
        whereClause += `${condition.aggregation}(${dataModel}.*) >= ${condition.threshold}`;
      }
    });

    // Add WHERE clause if exists
    if (whereClause) {
      query += ` where ${whereClause}`;
    }

    // Add GROUP BY clause
    if (primary_entity) {
      const mappedPrimary = mappedFields[primary_entity] || primary_entity;
      groupBy.push(`${dataModel}.${mappedPrimary}`);
    }
    
    if (secondary_entity) {
      const mappedSecondary = mappedFields[secondary_entity] || secondary_entity;
      groupBy.push(`${dataModel}.${mappedSecondary}`);
    }

    if (groupBy.length > 0) {
      query += ` by ${groupBy.join(', ')}`;
    }

    // Add time window if specified
    const timeCondition = conditions.find(c => c.time_window);
    if (timeCondition) {
      query = ` earliest=-${timeCondition.time_window} ${query}`;
    }

    // Handle sequence detection
    const sequenceCondition = conditions.find(c => c.sequence_followed_by);
    if (sequenceCondition) {
      query = this.buildSequenceQuery(query, sequenceCondition, mappedFields, dataModel);
    }

    return {
      query: query,
      parameters: {
        dataModel,
        mappedFields,
        conditions
      },
      description: `Splunk SPL query for ${dataModel} data model`
    };
  }

  buildChronicleQuery(detectionLogic, mappedFields) {
    const { conditions, primary_entity, secondary_entity } = detectionLogic;
    let query = 'events';
    let whereClause = [];

    // Build WHERE clause from conditions
    conditions.forEach(condition => {
      if (condition.field && condition.operator && condition.value) {
        const mappedField = mappedFields[condition.field] || condition.field;
        
        switch (condition.operator) {
          case 'equals':
            whereClause.push(`${mappedField} = "${condition.value}"`);
            break;
          case 'not_equals':
            whereClause.push(`${mappedField} != "${condition.value}"`);
            break;
          case 'contains':
            whereClause.push(`regexp_contains(${mappedField}, "${condition.value}")`);
            break;
          case 'regex':
            whereClause.push(`regexp_contains(${mappedField}, "${condition.value}")`);
            break;
          default:
            whereClause.push(`${mappedField} = "${condition.value}"`);
        }
      }
    });

    // Add WHERE clause if exists
    if (whereClause.length > 0) {
      query += ` | where ${whereClause.join(' AND ')}`;
    }

    // Add aggregations
    const aggregationCondition = conditions.find(c => c.aggregation);
    if (aggregationCondition && aggregationCondition.threshold) {
      query += ` | group_by ${this.buildChronicleGroupBy(primary_entity, secondary_entity, mappedFields)}`;
      query += ` | where count >= ${aggregationCondition.threshold}`;
    }

    // Add time window
    const timeCondition = conditions.find(c => c.time_window);
    if (timeCondition) {
      const timeWindow = this.convertTimeWindow(timeCondition.time_window);
      query += ` | within ${timeWindow}`;
    }

    return {
      query: query,
      parameters: {
        mappedFields,
        conditions
      },
      description: 'Chronicle UDM query'
    };
  }

  buildSequenceQuery(baseQuery, sequenceCondition, mappedFields, dataModel) {
    // For Splunk sequence detection, we use transaction or streamstats
    const { sequence_followed_by, within } = sequenceCondition;
    
    let sequenceQuery = baseQuery;
    
    if (within) {
      sequenceQuery += ` | transaction ${dataModel}.* maxspan=${within}`;
    } else {
      sequenceQuery += ` | transaction ${dataModel}.*`;
    }
    
    // Add condition for sequence
    if (sequence_followed_by) {
      const mappedField = mappedFields[sequence_followed_by] || sequence_followed_by;
      sequenceQuery += ` | where ${dataModel}.${mappedField}="${sequence_followed_by}"`;
    }
    
    return sequenceQuery;
  }

  buildChronicleGroupBy(primaryEntity, secondaryEntity, mappedFields) {
    const groupBy = [];
    
    if (primaryEntity) {
      const mappedPrimary = mappedFields[primaryEntity] || primaryEntity;
      groupBy.push(mappedPrimary);
    }
    
    if (secondaryEntity) {
      const mappedSecondary = mappedFields[secondaryEntity] || secondaryEntity;
      groupBy.push(mappedSecondary);
    }
    
    return groupBy.length > 0 ? groupBy.join(', ') : 'metadata.event_timestamp.seconds';
  }

  convertTimeWindow(timeWindow) {
    // Convert time window format (e.g., "5m" to "5 minutes")
    const match = timeWindow.match(/^(\d+)([smhd])$/);
    if (!match) return timeWindow;
    
    const [, amount, unit] = match;
    const unitMap = {
      's': 'seconds',
      'm': 'minutes', 
      'h': 'hours',
      'd': 'days'
    };
    
    return `${amount} ${unitMap[unit]}`;
  }

  generateResponseActions(useCase, platform) {
    const { response_orchestration } = useCase;
    const actions = [];

    if (!response_orchestration) {
      return [];
    }

    const { automated_actions, conditional_actions, approval_required } = response_orchestration;

    // Generate platform-specific actions
    automated_actions.forEach(action => {
      actions.push(this.generatePlatformAction(action, platform, false));
    });

    // Generate conditional actions
    if (conditional_actions) {
      conditional_actions.forEach(conditional => {
        const action = this.generatePlatformAction(conditional.then, platform, true, conditional.if);
        actions.push(action);
      });
    }

    return {
      platform,
      actions,
      approval_required: approval_required || false
    };
  }

  generatePlatformAction(action, platform, isConditional = false, condition = null) {
    const baseAction = {
      name: action,
      description: this.getActionDescription(action),
      platform: platform
    };

    if (isConditional) {
      baseAction.conditional = true;
      baseAction.condition = condition;
    }

    // Add platform-specific implementation
    switch (platform.toLowerCase()) {
      case 'splunk':
        baseAction.implementation = this.getSplunkAction(action);
        break;
      case 'chronicle':
        baseAction.implementation = this.getChronicleAction(action);
        break;
      default:
        baseAction.implementation = this.getGenericAction(action);
    }

    return baseAction;
  }

  getActionDescription(action) {
    const descriptions = {
      'reset_password': 'Reset user password and require change on next login',
      'revoke_sessions': 'Revoke all active user sessions',
      'block_source_ip': 'Block malicious IP address at firewall',
      'isolate_host': 'Isolate compromised host from network',
      'block_hash': 'Block malicious file hash across endpoints',
      'disable_account': 'Temporarily disable user account',
      'force_mfa_revalidation': 'Force MFA revalidation for user sessions',
      'collect_forensic_logs': 'Collect and preserve forensic evidence',
      'quarantine_email': 'Quarantine suspicious email messages',
      'block_url': 'Block access to malicious URL',
      'escalate_to_analyst': 'Escalate incident to security analyst'
    };

    return descriptions[action] || `Execute ${action} action`;
  }

  getSplunkAction(action) {
    const implementations = {
      'reset_password': '| sendemail to="$user$" subject="Password Reset Required" message="Your password has been reset. Please contact IT support."',
      'block_source_ip': '| splunksearch index=firewall src_ip="$src_ip$" | stats count | where count>0 | eval block_action="block" | outputlookup firewall_blocks.csv',
      'isolate_host': '| splunksearch index=endpoint hostname="$hostname$" | stats count | where count>0 | eval isolate_action="isolate" | outputlookup endpoint_isolation.csv',
      'escalate_to_analyst': '| sendemail to="soc@company.com" subject="Security Alert: $use_case_name$" message="Immediate attention required for $use_case_name$ detected."'
    };

    return implementations[action] || `# Implementation for ${action} needed`;
  }

  getChronicleAction(action) {
    const implementations = {
      'reset_password': 'gcp_identity.reset_password(user_id="$user$")',
      'block_source_ip': 'gcp_network.firewall.create_rule(source_ip="$src_ip$", action="DENY")',
      'isolate_host': 'endpoint.isolate(hostname="$hostname$")',
      'escalate_to_analyst': 'alert.create(severity="HIGH", message="$use_case_name$ detected", assignee="soc@company.com")'
    };

    return implementations[action] || `// Implementation for ${action} needed`;
  }

  getGenericAction(action) {
    return `// Generic implementation for ${action}`;
  }

  validateQuery(query, platform) {
    const errors = [];
    const warnings = [];

    if (!query || !query.trim()) {
      errors.push('Query cannot be empty');
    }

    switch (platform.toLowerCase()) {
      case 'splunk':
        this.validateSplunkQuery(query, errors, warnings);
        break;
      case 'chronicle':
        this.validateChronicleQuery(query, errors, warnings);
        break;
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  validateSplunkQuery(query, errors, warnings) {
    // Basic SPL validation
    if (!query.includes('|')) {
      warnings.push('Query may not be a valid SPL query (missing pipe operator)');
    }

    if (query.includes('tstats') && !query.includes('datamodel=')) {
      errors.push('tstats query requires datamodel parameter');
    }

    if (query.includes('transaction') && !query.includes('maxspan') && !query.includes('maxpause')) {
      warnings.push('Transaction command should include maxspan or maxpause for better performance');
    }
  }

  validateChronicleQuery(query, errors, warnings) {
    // Basic Chronicle query validation
    if (!query.startsWith('events')) {
      warnings.push('Chronicle queries typically start with "events"');
    }

    if (query.includes('group_by') && !query.includes('where')) {
      warnings.push('Group by without where clause may return too many results');
    }

    if (query.includes('within') && !query.match(/within\s+\d+\s+\w+/)) {
      errors.push('Invalid time window format in within clause');
    }
  }
}

module.exports = QueryGenerator;
