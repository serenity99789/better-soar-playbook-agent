const axios = require('axios');

class LLMEngine {
  constructor() {
    this.providers = {
      'gemini': {
        apiKey: process.env.GEMINI_API_KEY,
        baseURL: 'https://generativelanguage.googleapis.com/v1beta',
        model: 'gemini-1.5-pro'
      },
      'openai': {
        apiKey: process.env.OPENAI_API_KEY,
        baseURL: 'https://api.openai.com/v1',
        model: 'gpt-4-turbo-preview'
      },
      'claude': {
        apiKey: process.env.ANTHROPIC_API_KEY,
        baseURL: 'https://api.anthropic.com/v1',
        model: 'claude-3-sonnet-20240229'
      }
    };
    
    this.defaultProvider = 'gemini';
    this.fallbackProvider = 'openai';
  }

  async processInput(input, context = {}) {
    try {
      const provider = this.selectBestProvider(context);
      const processed = await this.callLLM(input, provider, context);
      
      return {
        success: true,
        provider: provider,
        processed_input: processed,
        confidence: this.calculateConfidence(processed),
        metadata: {
          model: this.providers[provider].model,
          processing_time: processed.processing_time,
          tokens_used: processed.tokens_used
        }
      };
    } catch (error) {
      console.error(`LLM processing failed with ${this.defaultProvider}:`, error);
      
      // Try fallback provider
      try {
        const fallback = await this.callLLM(input, this.fallbackProvider, context);
        return {
          success: true,
          provider: this.fallbackProvider,
          processed_input: fallback,
          confidence: this.calculateConfidence(fallback),
          fallback_used: true,
          metadata: {
            model: this.providers[this.fallbackProvider].model,
            processing_time: fallback.processing_time,
            tokens_used: fallback.tokens_used
          }
        };
      } catch (fallbackError) {
        return {
          success: false,
          error: `All LLM providers failed: ${error.message}, ${fallbackError.message}`,
          fallback_processed: this.fallbackProcessing(input)
        };
      }
    }
  }

  selectBestProvider(context) {
    // Smart provider selection based on input type and requirements
    if (context.complexity === 'high') {
      return 'claude'; // Best for complex reasoning
    } else if (context.speed === 'critical') {
      return 'gemini'; // Fastest response time
    } else if (context.accuracy === 'critical') {
      return 'openai'; // Most reliable for structured output
    }
    
    return this.defaultProvider;
  }

  async callLLM(input, provider, context) {
    const config = this.providers[provider];
    
    if (!config.apiKey) {
      throw new Error(`API key not configured for ${provider}`);
    }

    const prompt = this.buildPrompt(input, context, provider);
    
    switch (provider) {
      case 'gemini':
        return await this.callGemini(prompt, config);
      case 'openai':
        return await this.callOpenAI(prompt, config);
      case 'claude':
        return await this.callClaude(prompt, config);
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }
  }

  buildPrompt(input, context, provider) {
    const basePrompt = `
You are an expert cybersecurity analyst and SOAR (Security Orchestration, Automation, and Response) specialist. 
Your task is to analyze security events and extract structured information for playbook generation.

INPUT: ${input}

CONTEXT: ${JSON.stringify(context, null, 2)}

Please extract and return the following information in JSON format:
{
  "event_type": "type of security event",
  "entities": {
    "users": ["list of user accounts involved"],
    "ips": ["list of IP addresses"],
    "hosts": ["list of hostnames"],
    "files": ["list of file hashes or names"],
    "urls": ["list of URLs or domains"]
  },
  "mitre_techniques": ["list of relevant MITRE ATT&CK technique IDs"],
  "severity": "Low|Medium|High|Critical",
  "risk_factors": ["list of specific risk factors"],
  "recommended_actions": ["list of immediate response actions"],
  "confidence_score": 0.0-1.0,
  "analysis_summary": "brief summary of the security event"
}

Focus on:
- Accurate MITRE ATT&CK technique mapping
- Proper severity assessment
- Actionable response recommendations
- Risk-based prioritization
`;

    // Provider-specific optimizations
    switch (provider) {
      case 'gemini':
        return `${basePrompt}\n\nProvide concise, structured JSON output optimized for speed.`;
      case 'openai':
        return `${basePrompt}\n\nProvide detailed, accurate JSON with comprehensive analysis.`;
      case 'claude':
        return `${basePrompt}\n\nProvide thoughtful, well-reasoned JSON with security expertise.`;
      default:
        return basePrompt;
    }
  }

  async callGemini(prompt, config) {
    const startTime = Date.now();
    
    const response = await axios.post(
      `${config.baseURL}/models/${config.model}:generateContent?key=${config.apiKey}`,
      {
        contents: [{
          parts: [{
            text: prompt
          }]
        }],
        generationConfig: {
          temperature: 0.1,
          maxOutputTokens: 2048,
          responseMimeType: "application/json"
        }
      },
      {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 30000
      }
    );

    const processingTime = Date.now() - startTime;
    
    return {
      content: response.data.candidates[0].content.parts[0].text,
      processing_time: processingTime,
      tokens_used: response.data.usageMetadata?.totalTokenCount || 0,
      provider: 'gemini'
    };
  }

  async callOpenAI(prompt, config) {
    const startTime = Date.now();
    
    const response = await axios.post(
      `${config.baseURL}/chat/completions`,
      {
        model: config.model,
        messages: [
          {
            role: 'system',
            content: 'You are a cybersecurity expert specializing in SOAR playbook generation. Always respond with valid JSON.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.1,
        max_tokens: 2048,
        response_format: { type: 'json_object' }
      },
      {
        headers: {
          'Authorization': `Bearer ${config.apiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: 45000
      }
    );

    const processingTime = Date.now() - startTime;
    
    return {
      content: response.data.choices[0].message.content,
      processing_time: processingTime,
      tokens_used: response.data.usage.total_tokens,
      provider: 'openai'
    };
  }

  async callClaude(prompt, config) {
    const startTime = Date.now();
    
    const response = await axios.post(
      `${config.baseURL}/messages`,
      {
        model: config.model,
        max_tokens: 2048,
        temperature: 0.1,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ]
      },
      {
        headers: {
          'x-api-key': config.apiKey,
          'anthropic-version': '2023-06-01',
          'Content-Type': 'application/json'
        },
        timeout: 60000
      }
    );

    const processingTime = Date.now() - startTime;
    
    return {
      content: response.data.content[0].text,
      processing_time: processingTime,
      tokens_used: response.data.usage.input_tokens + response.data.usage.output_tokens,
      provider: 'claude'
    };
  }

  calculateConfidence(processed) {
    // Calculate confidence based on various factors
    let confidence = 0.5; // Base confidence
    
    // Boost confidence if structured properly
    try {
      const parsed = JSON.parse(processed.content);
      if (parsed.mitre_techniques && parsed.mitre_techniques.length > 0) {
        confidence += 0.2;
      }
      if (parsed.entities && Object.keys(parsed.entities).length > 0) {
        confidence += 0.15;
      }
      if (parsed.confidence_score && parsed.confidence_score > 0.7) {
        confidence += 0.15;
      }
    } catch (e) {
      confidence -= 0.2; // Penalize if not valid JSON
    }
    
    // Factor in processing time (faster is better for real-time)
    if (processed.processing_time < 5000) {
      confidence += 0.1;
    }
    
    return Math.min(1.0, Math.max(0.0, confidence));
  }

  fallbackProcessing(input) {
    // Fallback to rule-based processing when LLMs fail
    const fallback = {
      content: JSON.stringify({
        event_type: 'unknown',
        entities: {
          users: [],
          ips: [],
          hosts: [],
          files: [],
          urls: []
        },
        mitre_techniques: [],
        severity: 'Medium',
        risk_factors: ['LLM processing failed'],
        recommended_actions: ['manual_review'],
        confidence_score: 0.3,
        analysis_summary: 'Fallback processing due to LLM unavailability'
      }),
      processing_time: 100,
      tokens_used: 0,
      provider: 'fallback'
    };
    
    return fallback;
  }

  async enhancePlaybook(playbook, enhancementType = 'comprehensive') {
    try {
      const prompt = `
Enhance this SOAR playbook for better security coverage and operational efficiency:

CURRENT PLAYBOOK:
${JSON.stringify(playbook, null, 2)}

ENHANCEMENT TYPE: ${enhancementType}

Please provide enhancements in the following areas:
1. MITRE ATT&CK technique coverage gaps
2. Additional detection logic improvements
3. Response action optimization
4. Risk assessment refinements
5. Compliance considerations

Return enhanced playbook in the same JSON format with improvements integrated.
`;

      const result = await this.processInput(prompt, {
        type: 'playbook_enhancement',
        complexity: 'high',
        accuracy: 'critical'
      });

      if (result.success) {
        const enhanced = JSON.parse(result.processed_input.content);
        return {
          original_playbook: playbook,
          enhanced_playbook: enhanced,
          improvements: this.identifyImprovements(playbook, enhanced),
          provider: result.provider,
          confidence: result.confidence
        };
      }

      return { success: false, error: result.error };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  identifyImprovements(original, enhanced) {
    const improvements = [];
    
    // Compare MITRE techniques
    if (enhanced.mitre_techniques && enhanced.mitre_techniques.length > (original.mitre_techniques || []).length) {
      improvements.push({
        category: 'mitre_coverage',
        description: `Added ${enhanced.mitre_techniques.length - (original.mitre_techniques || []).length} new MITRE techniques`,
        impact: 'high'
      });
    }
    
    // Compare detection logic
    if (enhanced.detection_logic && original.detection_logic) {
      if (enhanced.detection_logic.conditions && enhanced.detection_logic.conditions.length > original.detection_logic.conditions.length) {
        improvements.push({
          category: 'detection_enhancement',
          description: `Added ${enhanced.detection_logic.conditions.length - original.detection_logic.conditions.length} new detection conditions`,
          impact: 'medium'
        });
      }
    }
    
    // Compare response actions
    if (enhanced.response_orchestration && original.response_orchestration) {
      const originalActions = original.response_orchestration.automated_actions || [];
      const enhancedActions = enhanced.response_orchestration.automated_actions || [];
      
      if (enhancedActions.length > originalActions.length) {
        improvements.push({
          category: 'response_optimization',
          description: `Added ${enhancedActions.length - originalActions.length} new response actions`,
          impact: 'medium'
        });
      }
    }
    
    return improvements;
  }

  async validatePlaybook(playbook) {
    const prompt = `
Validate this SOAR playbook for security best practices and completeness:

PLAYBOOK TO VALIDATE:
${JSON.stringify(playbook, null, 2)}

Please validate and return:
{
  "validation_score": 0.0-1.0,
  "issues_found": [
    {
      "category": "mitre_mapping|detection_logic|risk_assessment|response_actions|compliance",
      "severity": "Low|Medium|High|Critical",
      "description": "description of the issue",
      "recommendation": "how to fix the issue"
    }
  ],
  "missing_elements": ["list of missing playbook elements"],
  "best_practices_violations": ["list of best practices not followed"],
  "overall_assessment": "summary of playbook quality"
}

Focus on:
- MITRE ATT&CK technique accuracy
- Detection logic completeness
- Risk assessment appropriateness
- Response action effectiveness
- Industry best practices compliance
`;

    const result = await this.processInput(prompt, {
      type: 'validation',
      accuracy: 'critical',
      complexity: 'high'
    });

    return result.success ? JSON.parse(result.processed_input.content) : { error: result.error };
  }

  getProviderStatus() {
    const status = {};
    
    Object.keys(this.providers).forEach(provider => {
      const config = this.providers[provider];
      status[provider] = {
        available: !!config.apiKey,
        model: config.model,
        configured: !!config.apiKey
      };
    });
    
    return status;
  }

  setDefaultProvider(provider) {
    if (this.providers[provider]) {
      this.defaultProvider = provider;
      return true;
    }
    return false;
  }
}

module.exports = LLMEngine;
