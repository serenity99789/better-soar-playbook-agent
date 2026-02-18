const fs = require('fs-extra');
const path = require('path');
const FieldMappingEngine = require('./FieldMappingEngine');
const MITREMapper = require('./MITREMapper');

class ReverseQueryEngine {
  constructor() {
    this.fieldMapper = new FieldMappingEngine();
    this.mitreMapper = new MITREMapper();
    this.playbookStore = new Map(); // In-memory store for demo
    this.loadStoredPlaybooks();
  }

  async search(query, platform, filters = {}) {
    try {
      const searchResults = {
        query: query,
        platform: platform,
        filters: filters,
        results: [],
        metadata: {
          total_results: 0,
          search_time: new Date().toISOString()
        }
      };

      // Parse the query to extract key elements
      const parsedQuery = this.parseQuery(query, platform);
      
      // Search through stored playbooks
      const matchingPlaybooks = this.searchPlaybooks(parsedQuery, platform, filters);
      
      // Generate reverse queries for each match
      for (const playbook of matchingPlaybooks) {
        const reverseQueries = this.generateReverseQueries(playbook, parsedQuery, platform);
        
        searchResults.results.push({
          playbook: playbook,
          reverse_queries: reverseQueries,
          relevance_score: this.calculateRelevanceScore(playbook, parsedQuery),
          matched_elements: this.getMatchedElements(playbook, parsedQuery)
        });
      }

      // Sort by relevance score
      searchResults.results.sort((a, b) => b.relevance_score - a.relevance_score);
      searchResults.metadata.total_results = searchResults.results.length;

      return searchResults;
    } catch (error) {
      throw new Error(`Reverse query search failed: ${error.message}`);
    }
  }

  parseQuery(query, platform) {
    const parsed = {
      original_query: query,
      platform: platform,
      elements: {
        fields: [],
        values: [],
        operators: [],
        functions: [],
        tables: [],
        conditions: []
      }
    };

    // Extract platform-specific elements
    switch (platform.toLowerCase()) {
      case 'splunk':
        return this.parseSplunkQuery(query, parsed);
      case 'chronicle':
        return this.parseChronicleQuery(query, parsed);
      default:
        return this.parseGenericQuery(query, parsed);
    }
  }

  parseSplunkQuery(query, parsed) {
    // Extract fields from SPL
    const fieldPattern = /(\w+(?:\.\w+)*)\s*=\s*"?([^"\s]+)"?/g;
    let match;
    
    while ((match = fieldPattern.exec(query)) !== null) {
      parsed.elements.fields.push(match[1]);
      parsed.elements.values.push(match[2]);
    }

    // Extract functions
    const functionPattern = /\b(tstats|stats|transaction|streamstats|eval|where|by)\b/g;
    while ((match = functionPattern.exec(query)) !== null) {
      parsed.elements.functions.push(match[1]);
    }

    // Extract data models
    const dataModelPattern = /datamodel=(\w+)/g;
    while ((match = dataModelPattern.exec(query)) !== null) {
      parsed.elements.tables.push(match[1]);
    }

    // Extract conditions
    const conditionPattern = /\b(where|if)\s+([^|]+)/g;
    while ((match = conditionPattern.exec(query)) !== null) {
      parsed.elements.conditions.push(match[2].trim());
    }

    return parsed;
  }

  parseChronicleQuery(query, parsed) {
    // Extract fields from UDM
    const fieldPattern = /(\w+(?:\.\w+)*)\s*=\s*"?([^"\s]+)"?/g;
    let match;
    
    while ((match = fieldPattern.exec(query)) !== null) {
      parsed.elements.fields.push(match[1]);
      parsed.elements.values.push(match[2]);
    }

    // Extract functions
    const functionPattern = /\b(events|group_by|where|within|regexp_contains)\b/g;
    while ((match = functionPattern.exec(query)) !== null) {
      parsed.elements.functions.push(match[1]);
    }

    // Extract conditions
    const conditionPattern = /where\s+([^|]+)/g;
    while ((match = conditionPattern.exec(query)) !== null) {
      parsed.elements.conditions.push(match[1].trim());
    }

    return parsed;
  }

  parseGenericQuery(query, parsed) {
    // Generic parsing for other platforms
    const fieldPattern = /(\w+)\s*=\s*"?([^"\s]+)"?/g;
    let match;
    
    while ((match = fieldPattern.exec(query)) !== null) {
      parsed.elements.fields.push(match[0]);
      parsed.elements.values.push(match[1]);
    }

    return parsed;
  }

  searchPlaybooks(parsedQuery, platform, filters) {
    const matchingPlaybooks = [];
    
    for (const [id, playbook] of this.playbookStore) {
      if (this.isPlaybookMatch(playbook, parsedQuery, platform, filters)) {
        matchingPlaybooks.push(playbook);
      }
    }

    return matchingPlaybooks;
  }

  isPlaybookMatch(playbook, parsedQuery, platform, filters) {
    // Check platform match
    if (playbook.platform !== platform) {
      return false;
    }

    // Check filters
    if (filters.category && playbook.use_case.use_case_metadata.category !== filters.category) {
      return false;
    }

    if (filters.severity && playbook.use_case.risk_model.base_severity !== filters.severity) {
      return false;
    }

    if (filters.mitre_technique) {
      const techniques = playbook.use_case.mitre_techniques;
      if (!techniques.includes(filters.mitre_technique)) {
        return false;
      }
    }

    // Check query elements match
    return this.checkQueryElementsMatch(playbook, parsedQuery);
  }

  checkQueryElementsMatch(playbook, parsedQuery) {
    const playbookQueries = playbook.queries || [];
    
    for (const query of playbookQueries) {
      if (this.queryElementsMatch(query, parsedQuery)) {
        return true;
      }
    }

    return false;
  }

  queryElementsMatch(query, parsedQuery) {
    // Check field matches
    const queryFields = this.extractFieldsFromQuery(query.query);
    const fieldMatches = queryFields.filter(field => 
      parsedQuery.elements.fields.includes(field)
    ).length;

    // Check function matches
    const functionMatches = parsedQuery.elements.functions.filter(func =>
      query.query.toLowerCase().includes(func.toLowerCase())
    ).length;

    // Calculate match score
    const totalElements = parsedQuery.elements.fields.length + parsedQuery.elements.functions.length;
    const matchedElements = fieldMatches + functionMatches;
    
    return totalElements > 0 && (matchedElements / totalElements) >= 0.3; // 30% match threshold
  }

  extractFieldsFromQuery(query) {
    const fields = [];
    const fieldPattern = /(\w+(?:\.\w+)*)\s*=/g;
    let match;
    
    while ((match = fieldPattern.exec(query)) !== null) {
      fields.push(match[1]);
    }
    
    return fields;
  }

  generateReverseQueries(playbook, parsedQuery, platform) {
    const reverseQueries = [];
    
    // Generate field-based reverse queries
    const fieldReverseQueries = this.generateFieldReverseQueries(playbook, parsedQuery, platform);
    reverseQueries.push(...fieldReverseQueries);
    
    // Generate technique-based reverse queries
    const techniqueReverseQueries = this.generateTechniqueReverseQueries(playbook, parsedQuery, platform);
    reverseQueries.push(...techniqueReverseQueries);
    
    // Generate pattern-based reverse queries
    const patternReverseQueries = this.generatePatternReverseQueries(playbook, parsedQuery, platform);
    reverseQueries.push(...patternReverseQueries);
    
    return reverseQueries;
  }

  generateFieldReverseQueries(playbook, parsedQuery, platform) {
    const queries = [];
    const playbookFields = playbook.use_case.normalized_fields;
    const mappedFields = playbook.use_case.platform_mapping[platform === 'splunk' ? 'splunk_cim' : 'google_udm'];
    
    for (const [normalField, mappedField] of Object.entries(mappedFields)) {
      if (parsedQuery.elements.fields.includes(mappedField)) {
        const reverseQuery = this.createFieldReverseQuery(normalField, mappedField, playbook, platform);
        queries.push(reverseQuery);
      }
    }
    
    return queries;
  }

  generateTechniqueReverseQueries(playbook, parsedQuery, platform) {
    const queries = [];
    const techniques = playbook.use_case.mitre_techniques;
    
    for (const techniqueId of techniques) {
      const technique = this.mitreMapper.getTechniqueById(techniqueId);
      if (technique) {
        const reverseQuery = this.createTechniqueReverseQuery(technique, playbook, platform);
        queries.push(reverseQuery);
      }
    }
    
    return queries;
  }

  generatePatternReverseQueries(playbook, parsedQuery, platform) {
    const queries = [];
    
    // Generate queries based on detection patterns
    const detectionLogic = playbook.use_case.detection_logic;
    
    if (detectionLogic.conditions) {
      for (const condition of detectionLogic.conditions) {
        if (condition.aggregation) {
          const reverseQuery = this.createAggregationReverseQuery(condition, playbook, platform);
          queries.push(reverseQuery);
        }
      }
    }
    
    return queries;
  }

  createFieldReverseQuery(normalField, mappedField, playbook, platform) {
    const baseQuery = {
      type: 'field_reverse',
      field: normalField,
      mapped_field: mappedField,
      description: `Reverse query for ${normalField} field`,
      platform: platform
    };

    switch (platform.toLowerCase()) {
      case 'splunk':
        baseQuery.query = `| tstats summariesonly=true count from datamodel=* where *=${mappedField} by ${mappedField} | head 10`;
        break;
      case 'chronicle':
        baseQuery.query = `events | where ${mappedField} != "" | group_by ${mappedField} | limit 10`;
        break;
      default:
        baseQuery.query = `SELECT ${mappedField}, COUNT(*) FROM events WHERE ${mappedField} IS NOT NULL GROUP BY ${mappedField} LIMIT 10`;
    }

    return baseQuery;
  }

  createTechniqueReverseQuery(technique, playbook, platform) {
    const baseQuery = {
      type: 'technique_reverse',
      technique: technique,
      description: `Reverse query for ${technique.name} (${technique.id})`,
      platform: platform
    };

    switch (platform.toLowerCase()) {
      case 'splunk':
        baseQuery.query = `| tstats summariesonly=true count from datamodel=* where *="${technique.name}" OR *="${technique.id}" by _time | head 10`;
        break;
      case 'chronicle':
        baseQuery.query = `events | where metadata.event_type="${technique.name}" OR rule.name="${technique.id}" | limit 10`;
        break;
      default:
        baseQuery.query = `SELECT * FROM events WHERE technique_name="${technique.name}" OR technique_id="${technique.id}" LIMIT 10`;
    }

    return baseQuery;
  }

  createAggregationReverseQuery(condition, playbook, platform) {
    const baseQuery = {
      type: 'aggregation_reverse',
      aggregation: condition.aggregation,
      threshold: condition.threshold,
      description: `Reverse query for aggregation pattern`,
      platform: platform
    };

    switch (platform.toLowerCase()) {
      case 'splunk':
        baseQuery.query = `| tstats summariesonly=true ${condition.aggregation} from datamodel=* by * | where ${condition.aggregation} >= ${condition.threshold - 5} | head 10`;
        break;
      case 'chronicle':
        baseQuery.query = `events | group_by * | where count >= ${condition.threshold - 5} | limit 10`;
        break;
      default:
        baseQuery.query = `SELECT *, COUNT(*) as count FROM events GROUP BY * HAVING count >= ${condition.threshold - 5} LIMIT 10`;
    }

    return baseQuery;
  }

  calculateRelevanceScore(playbook, parsedQuery) {
    let score = 0;
    
    // Base score for having matching platform
    score += 10;
    
    // Score for field matches
    const fieldMatches = this.countFieldMatches(playbook, parsedQuery);
    score += fieldMatches * 15;
    
    // Score for function matches
    const functionMatches = this.countFunctionMatches(playbook, parsedQuery);
    score += functionMatches * 10;
    
    // Score for technique matches
    const techniqueMatches = this.countTechniqueMatches(playbook, parsedQuery);
    score += techniqueMatches * 20;
    
    // Score for category relevance
    if (this.isCategoryRelevant(playbook, parsedQuery)) {
      score += 15;
    }
    
    return Math.min(100, score);
  }

  countFieldMatches(playbook, parsedQuery) {
    const playbookFields = Object.values(playbook.use_case.platform_mapping[
      playbook.platform === 'splunk' ? 'splunk_cim' : 'google_udm'
    ]);
    
    return parsedQuery.elements.fields.filter(field => 
      playbookFields.includes(field)
    ).length;
  }

  countFunctionMatches(playbook, parsedQuery) {
    const playbookQueries = playbook.queries || [];
    let matches = 0;
    
    for (const query of playbookQueries) {
      for (const func of parsedQuery.elements.functions) {
        if (query.query.toLowerCase().includes(func.toLowerCase())) {
          matches++;
        }
      }
    }
    
    return matches;
  }

  countTechniqueMatches(playbook, parsedQuery) {
    const techniques = playbook.use_case.mitre_techniques;
    let matches = 0;
    
    for (const techniqueId of techniques) {
      const technique = this.mitreMapper.getTechniqueById(techniqueId);
      if (technique) {
        // Check if technique name appears in query
        if (parsedQuery.original_query.toLowerCase().includes(technique.name.toLowerCase())) {
          matches++;
        }
        // Check if technique ID appears in query
        if (parsedQuery.original_query.includes(technique.id)) {
          matches++;
        }
      }
    }
    
    return matches;
  }

  isCategoryRelevant(playbook, parsedQuery) {
    const category = playbook.use_case.use_case_metadata.category.toLowerCase();
    const query = parsedQuery.original_query.toLowerCase();
    
    const categoryKeywords = {
      'identity': ['user', 'login', 'auth', 'password', 'account'],
      'malware': ['malware', 'virus', 'hash', 'process', 'file'],
      'phishing': ['email', 'phish', 'attachment', 'link'],
      'network': ['network', 'ip', 'port', 'traffic']
    };
    
    const keywords = categoryKeywords[category] || [];
    return keywords.some(keyword => query.includes(keyword));
  }

  getMatchedElements(playbook, parsedQuery) {
    const matched = {
      fields: [],
      functions: [],
      techniques: [],
      patterns: []
    };
    
    // Matched fields
    const playbookFields = Object.values(playbook.use_case.platform_mapping[
      playbook.platform === 'splunk' ? 'splunk_cim' : 'google_udm'
    ]);
    
    matched.fields = parsedQuery.elements.fields.filter(field => 
      playbookFields.includes(field)
    );
    
    // Matched functions
    const playbookQueries = playbook.queries || [];
    for (const func of parsedQuery.elements.functions) {
      for (const query of playbookQueries) {
        if (query.query.toLowerCase().includes(func.toLowerCase())) {
          matched.functions.push(func);
          break;
        }
      }
    }
    
    // Matched techniques
    const techniques = playbook.use_case.mitre_techniques;
    for (const techniqueId of techniques) {
      const technique = this.mitreMapper.getTechniqueById(techniqueId);
      if (technique && parsedQuery.original_query.toLowerCase().includes(technique.name.toLowerCase())) {
        matched.techniques.push(technique);
      }
    }
    
    return matched;
  }

  loadStoredPlaybooks() {
    // Load sample playbooks for demonstration
    const samplePlaybooks = [
      {
        playbook_id: 'sample-1',
        playbook_name: 'Multiple Failed Logins',
        platform: 'splunk',
        use_case: {
          use_case_metadata: {
            category: 'Identity',
            mitre_techniques: ['T1110']
          },
          normalized_fields: {
            username: 'user',
            source_ip: 'src'
          },
          platform_mapping: {
            splunk_cim: {
              username: 'user',
              source_ip: 'src'
            }
          },
          risk_model: {
            base_severity: 'High'
          }
        },
        queries: [
          {
            query: '| tstats count from datamodel=Authentication where Authentication.action="failure" by Authentication.user, Authentication.src'
          }
        ]
      },
      {
        playbook_id: 'sample-2',
        playbook_name: 'Malware Hash Detection',
        platform: 'chronicle',
        use_case: {
          use_case_metadata: {
            category: 'Malware',
            mitre_techniques: ['T1204']
          },
          normalized_fields: {
            file_hash: 'target.file.sha256'
          },
          platform_mapping: {
            google_udm: {
              file_hash: 'target.file.sha256'
            }
          },
          risk_model: {
            base_severity: 'High'
          }
        },
        queries: [
          {
            query: 'events | where target.file.sha256 != "" | group_by target.file.sha256'
          }
        ]
      }
    ];
    
    samplePlaybooks.forEach(playbook => {
      this.playbookStore.set(playbook.playbook_id, playbook);
    });
  }

  storePlaybook(playbook) {
    this.playbookStore.set(playbook.playbook_id, playbook);
  }

  removePlaybook(playbookId) {
    return this.playbookStore.delete(playbookId);
  }

  getStoredPlaybooks() {
    return Array.from(this.playbookStore.values());
  }

  getPlaybookById(playbookId) {
    return this.playbookStore.get(playbookId);
  }
}

module.exports = ReverseQueryEngine;
