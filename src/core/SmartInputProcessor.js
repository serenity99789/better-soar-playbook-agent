const LLMEngine = require('./LLMEngine');
const InputProcessor = require('./InputProcessor');

class SmartInputProcessor extends InputProcessor {
  constructor() {
    super();
    this.llmEngine = new LLMEngine();
    this.inputHistory = [];
    this.contextMemory = new Map();
  }

  async processInput(input, type = 'text', options = {}) {
    try {
      // First, try traditional processing
      const traditionalResult = await super.processInput(input, type);
      
      // Then enhance with LLM processing
      const llmResult = await this.llmEngine.processInput(input, {
        input_type: type,
        traditional_result: traditionalResult,
        user_preferences: options.userPreferences || {},
        previous_context: this.getRelevantContext(input)
      });

      // Merge results intelligently
      const mergedResult = this.mergeProcessingResults(traditionalResult, llmResult);
      
      // Store in history for context
      this.addToHistory(input, mergedResult);
      
      return mergedResult;
    } catch (error) {
      console.error('Smart processing failed:', error);
      // Fallback to traditional processing
      return super.processInput(input, type);
    }
  }

  mergeProcessingResults(traditional, llm) {
    const merged = {
      ...traditional,
      llm_enhanced: true,
      llm_provider: llm.provider,
      processing_method: 'hybrid'
    };

    // Merge extracted fields with LLM insights
    if (llm.success && llm.processed_input) {
      try {
        const llmParsed = JSON.parse(llm.processed_input.content);
        
        // Enhance extracted fields
        merged.extractedFields = this.enhanceExtractedFields(
          traditional.extractedFields || {},
          llmParsed.entities || {}
        );
        
        // Enhance normalized data
        merged.normalizedData = this.enhanceNormalizedData(
          traditional.normalizedData || {},
          llmParsed
        );
        
        // Add LLM-specific insights
        merged.llm_insights = {
          event_type: llmParsed.event_type,
          mitre_techniques: llmParsed.mitre_techniques || [],
          severity: llmParsed.severity,
          risk_factors: llmParsed.risk_factors || [],
          recommended_actions: llmParsed.recommended_actions || [],
          confidence_score: llmParsed.confidence_score || 0.5,
          analysis_summary: llmParsed.analysis_summary || ''
        };
        
        // Update metadata
        merged.metadata = {
          ...traditional.metadata,
          llm_processing_time: llm.metadata.processing_time,
          llm_tokens_used: llm.metadata.tokens_used,
          llm_confidence: llm.confidence,
          processing_timestamp: new Date().toISOString()
        };
        
      } catch (parseError) {
        console.warn('Failed to parse LLM response:', parseError);
        merged.llm_parse_error = parseError.message;
      }
    }

    return merged;
  }

  enhanceExtractedFields(traditionalFields, llmEntities) {
    const enhanced = { ...traditionalFields };
    
    // Merge and deduplicate entities
    Object.keys(llmEntities).forEach(entityType => {
      const traditionalArray = traditionalFields[entityType] || [];
      const llmArray = Array.isArray(llmEntities[entityType]) ? llmEntities[entityType] : [];
      
      enhanced[entityType] = [...new Set([...traditionalArray, ...llmArray])];
    });
    
    return enhanced;
  }

  enhanceNormalizedData(traditionalData, llmParsed) {
    const enhanced = { ...traditionalData };
    
    // Update entity type based on LLM analysis
    if (llmParsed.event_type) {
      enhanced.entity_type = this.inferEntityTypeFromEvent(llmParsed.event_type);
    }
    
    // Enhance with LLM-extracted entities
    if (llmParsed.entities) {
      Object.keys(llmParsed.entities).forEach(entityType => {
        const entityArray = Array.isArray(llmParsed.entities[entityType]) ? 
          llmParsed.entities[entityType] : [];
        
        if (entityArray.length > 0) {
          const fieldName = this.mapEntityTypeToField(entityType);
          enhanced[fieldName] = entityArray[0]; // Take first/most relevant
        }
      });
    }
    
    // Update description with LLM summary
    if (llmParsed.analysis_summary) {
      enhanced.description = llmParsed.analysis_summary;
    }
    
    return enhanced;
  }

  inferEntityTypeFromEvent(eventType) {
    const eventMappings = {
      'authentication': 'user',
      'malware': 'file',
      'phishing': 'url',
      'network': 'ip',
      'privilege_escalation': 'user',
      'data_exfiltration': 'file',
      'command_and_control': 'ip'
    };
    
    return eventMappings[eventType.toLowerCase()] || enhanced.entity_type || 'unknown';
  }

  mapEntityTypeToField(entityType) {
    const fieldMappings = {
      'users': 'username',
      'ips': 'source_ip',
      'hosts': 'hostname',
      'files': 'file_hash',
      'urls': 'url'
    };
    
    return fieldMappings[entityType] || entityType;
  }

  getRelevantContext(input) {
    // Find relevant context from memory based on input similarity
    const context = [];
    const inputLower = input.toLowerCase();
    
    for (const [key, value] of this.contextMemory.entries()) {
      if (key.toLowerCase().includes(inputLower.substring(0, 20))) {
        context.push(value);
      }
    }
    
    return context.slice(-3); // Return last 3 relevant contexts
  }

  addToHistory(input, result) {
    this.inputHistory.push({
      input: input,
      result: result,
      timestamp: new Date().toISOString()
    });
    
    // Keep history manageable
    if (this.inputHistory.length > 100) {
      this.inputHistory = this.inputHistory.slice(-50);
    }
    
    // Update context memory
    this.updateContextMemory(input, result);
  }

  updateContextMemory(input, result) {
    // Extract key concepts for context
    const concepts = this.extractConcepts(input);
    
    concepts.forEach(concept => {
      this.contextMemory.set(concept, {
        input: input,
        result: result.llm_insights || {},
        timestamp: new Date().toISOString()
      });
    });
    
    // Keep memory manageable
    if (this.contextMemory.size > 1000) {
      const entries = Array.from(this.contextMemory.entries());
      this.contextMemory = new Map(entries.slice(-500));
    }
  }

  extractConcepts(input) {
    // Simple concept extraction - could be enhanced with NLP
    const concepts = [];
    const words = input.toLowerCase().split(/\s+/);
    
    // Security-related keywords
    const securityKeywords = [
      'login', 'authentication', 'malware', 'phishing', 'brute force',
      'password', 'privilege', 'escalation', 'lateral', 'movement',
      'exfiltration', 'command', 'control', 'suspicious', 'anomaly'
    ];
    
    words.forEach(word => {
      if (securityKeywords.includes(word) || word.length > 6) {
        concepts.push(word);
      }
    });
    
    return [...new Set(concepts)];
  }

  async getSmartSuggestions(input, limit = 5) {
    try {
      const prompt = `
Based on this security input, provide smart suggestions for playbook generation:

INPUT: ${input}

Provide up to ${limit} suggestions for:
1. MITRE ATT&CK techniques that might be relevant
2. Additional data sources to consider
3. Risk factors to evaluate
4. Response actions to prioritize
5. Similar security events that might be related

Return as JSON array of suggestions with title, description, and priority.
`;

      const result = await this.llmEngine.processInput(prompt, {
        type: 'suggestions',
        speed: 'medium'
      });

      if (result.success) {
        try {
          return JSON.parse(result.processed_input.content);
        } catch (e) {
          return this.getDefaultSuggestions();
        }
      }
      
      return this.getDefaultSuggestions();
    } catch (error) {
      return this.getDefaultSuggestions();
    }
  }

  getDefaultSuggestions() {
    return [
      {
        title: "Review Authentication Logs",
        description: "Check for additional failed logins or unusual patterns",
        priority: "high"
      },
      {
        title: "Validate MITRE Techniques",
        description: "Ensure proper ATT&CK technique mapping",
        priority: "medium"
      },
      {
        title: "Assess Asset Criticality",
        description: "Determine importance of affected systems",
        priority: "medium"
      },
      {
        title: "Consider Time-based Analysis",
        description: "Evaluate patterns over different time windows",
        priority: "low"
      },
      {
        title: "Review Historical Incidents",
        description: "Check for similar past security events",
        priority: "low"
      }
    ];
  }

  async autoClassifyInput(input) {
    try {
      const prompt = `
Classify this security input into categories:

INPUT: ${input}

Return JSON with:
{
  "primary_category": "identity|malware|phishing|network|data_exfiltration|privilege_escalation",
  "confidence": 0.0-1.0,
  "secondary_categories": ["list of other possible categories"],
  "key_indicators": ["list of key security indicators"],
  "urgency_level": "low|medium|high|critical"
}

Focus on the most likely security category and key indicators.
`;

      const result = await this.llmEngine.processInput(prompt, {
        type: 'classification',
        speed: 'fast'
      });

      if (result.success) {
        try {
          return JSON.parse(result.processed_input.content);
        } catch (e) {
          return this.ruleBasedClassification(input);
        }
      }
      
      return this.ruleBasedClassification(input);
    } catch (error) {
      return this.ruleBasedClassification(input);
    }
  }

  ruleBasedClassification(input) {
    const inputLower = input.toLowerCase();
    
    // Rule-based classification
    if (inputLower.includes('login') || inputLower.includes('password') || inputLower.includes('authentication')) {
      return {
        primary_category: 'identity',
        confidence: 0.8,
        secondary_categories: ['malware'],
        key_indicators: ['authentication_failure', 'brute_force'],
        urgency_level: 'medium'
      };
    }
    
    if (inputLower.includes('malware') || inputLower.includes('virus') || inputLower.includes('hash')) {
      return {
        primary_category: 'malware',
        confidence: 0.9,
        secondary_categories: ['data_exfiltration'],
        key_indicators: ['file_hash', 'malicious_process'],
        urgency_level: 'high'
      };
    }
    
    if (inputLower.includes('phishing') || inputLower.includes('email') || inputLower.includes('attachment')) {
      return {
        primary_category: 'phishing',
        confidence: 0.85,
        secondary_categories: ['malware'],
        key_indicators: ['suspicious_email', 'malicious_url'],
        urgency_level: 'medium'
      };
    }
    
    // Default classification
    return {
      primary_category: 'network',
      confidence: 0.5,
      secondary_categories: [],
      key_indicators: ['anomaly'],
      urgency_level: 'low'
    };
  }

  getProcessingStats() {
    return {
      total_processed: this.inputHistory.length,
      llm_provider_status: this.llmEngine.getProviderStatus(),
      context_memory_size: this.contextMemory.size,
      average_confidence: this.calculateAverageConfidence(),
      processing_methods: this.getProcessingMethodDistribution()
    };
  }

  calculateAverageConfidence() {
    const confidences = this.inputHistory
      .filter(entry => entry.result.llm_confidence)
      .map(entry => entry.result.llm_confidence);
    
    if (confidences.length === 0) return 0;
    
    const sum = confidences.reduce((acc, val) => acc + val, 0);
    return sum / confidences.length;
  }

  getProcessingMethodDistribution() {
    const methods = this.inputHistory.reduce((acc, entry) => {
      const method = entry.result.processing_method || 'traditional';
      acc[method] = (acc[method] || 0) + 1;
      return acc;
    }, {});
    
    return methods;
  }

  clearHistory() {
    this.inputHistory = [];
    this.contextMemory.clear();
  }
}

module.exports = SmartInputProcessor;
