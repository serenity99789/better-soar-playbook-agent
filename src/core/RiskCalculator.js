class RiskCalculator {
  constructor() {
    this.baseRiskScores = {
      'Low': 25,
      'Medium': 50,
      'High': 75,
      'Critical': 100
    };

    this.mitreRiskWeights = {
      'T1098': 30,  // Account Manipulation
      'T1110': 25,  // Brute Force
      'T1110.003': 25,  // Password Spraying
      'T1078': 20,  // Valid Accounts
      'T1621': 20,  // MFA Fatigue
      'T1204': 15,  // User Execution
      'T1059.001': 15,  // PowerShell
      'T1566.001': 10,  // Spearphishing Attachment
      'T1566.002': 10,  // Spearphishing Link
      'T1566.003': 10   // Spearphishing via Service
    };

    this.entityRiskMultipliers = {
      'user': 1.0,
      'ip': 0.8,
      'file': 1.2,
      'url': 0.6
    };
  }

  calculateRiskScore(baseSeverity, mitreTechniques, normalizedData) {
    let riskScore = this.baseRiskScores[baseSeverity] || 50;
    
    // Add MITRE technique risk
    mitreTechniques.forEach(technique => {
      const techniqueId = typeof technique === 'string' ? technique : technique.id;
      riskScore += this.mitreRiskWeights[techniqueId] || 5;
    });
    
    // Apply entity type multiplier
    const entityType = normalizedData.entity_type || 'unknown';
    const multiplier = this.entityRiskMultipliers[entityType] || 1.0;
    riskScore *= multiplier;
    
    // Cap at 100
    return Math.min(100, Math.round(riskScore));
  }

  getRiskAdjustments(mitreTechniques, normalizedData) {
    const adjustments = [];
    
    // Privileged account adjustment
    if (this.isPrivilegedAccount(normalizedData)) {
      adjustments.push({
        condition: 'privileged_account',
        add_score: 25,
        description: 'Privileged account involved'
      });
    }
    
    // Impossible travel adjustment
    if (this.hasImpossibleTravel(normalizedData)) {
      adjustments.push({
        condition: 'impossible_travel',
        add_score: 20,
        description: 'Impossible travel detected'
      });
    }
    
    // High critical asset adjustment
    if (this.isHighCriticalAsset(normalizedData)) {
      adjustments.push({
        condition: 'high_critical_asset',
        add_score: 15,
        description: 'High criticality asset involved'
      });
    }
    
    // Server host adjustment
    if (this.isServerHost(normalizedData)) {
      adjustments.push({
        condition: 'server_host',
        add_score: 30,
        description: 'Server host affected'
      });
    }
    
    // External IP adjustment
    if (this.isExternalIP(normalizedData)) {
      adjustments.push({
        condition: 'external_ip',
        add_score: 10,
        description: 'External IP address'
      });
    }
    
    // Known malicious hash adjustment
    if (this.isKnownMaliciousHash(normalizedData)) {
      adjustments.push({
        condition: 'known_malicious_hash',
        add_score: 35,
        description: 'Known malicious file hash'
      });
    }
    
    // Admin account targeting adjustment
    if (this.isAdminAccountTargeted(mitreTechniques, normalizedData)) {
      adjustments.push({
        condition: 'admin_accounts_targeted',
        add_score: 25,
        description: 'Administrator accounts targeted'
      });
    }
    
    // VPN session adjustment
    if (this.hasVPNSession(normalizedData)) {
      adjustments.push({
        condition: 'vpn_session',
        add_score: 25,
        description: 'VPN session detected'
      });
    }
    
    // New country adjustment
    if (this.isNewCountry(normalizedData)) {
      adjustments.push({
        condition: 'new_country',
        add_score: 15,
        description: 'Login from new country'
      });
    }
    
    // Outside business hours adjustment
    if (this.isOutsideBusinessHours(normalizedData)) {
      adjustments.push({
        condition: 'outside_business_hours',
        add_score: 20,
        description: 'Activity outside business hours'
      });
    }
    
    return adjustments;
  }

  isPrivilegedAccount(normalizedData) {
    const privilegedIndicators = [
      'admin', 'administrator', 'root', 'sa', 'service',
      'privileged', 'elevated', 'sudo', 'domain admin'
    ];
    
    if (normalizedData.username) {
      const username = normalizedData.username.toLowerCase();
      return privilegedIndicators.some(indicator => username.includes(indicator));
    }
    
    return false;
  }

  hasImpossibleTravel(normalizedData) {
    // Check for indicators of impossible travel
    return normalizedData.description && 
           (normalizedData.description.toLowerCase().includes('impossible travel') ||
            normalizedData.description.toLowerCase().includes('geolocation') ||
            normalizedData.description.toLowerCase().includes('distance'));
  }

  isHighCriticalAsset(normalizedData) {
    const criticalIndicators = [
      'domain controller', 'dc', 'ad server', 'database', 'db',
      'critical', 'production', 'finance', 'hr', 'executive'
    ];
    
    if (normalizedData.hostname) {
      const hostname = normalizedData.hostname.toLowerCase();
      return criticalIndicators.some(indicator => hostname.includes(indicator));
    }
    
    return false;
  }

  isServerHost(normalizedData) {
    const serverIndicators = [
      'server', 'srv', 'dc', 'db', 'sql', 'web', 'app',
      'prod', 'production', 'enterprise'
    ];
    
    if (normalizedData.hostname) {
      const hostname = normalizedData.hostname.toLowerCase();
      return serverIndicators.some(indicator => hostname.includes(indicator));
    }
    
    return false;
  }

  isExternalIP(normalizedData) {
    if (!normalizedData.source_ip) return false;
    
    const ip = normalizedData.source_ip;
    
    // Check for private IP ranges
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./
    ];
    
    return !privateRanges.some(range => range.test(ip));
  }

  isKnownMaliciousHash(normalizedData) {
    // This would typically check against threat intelligence
    // For now, assume any hash in the context is suspicious
    return normalizedData.file_hash && normalizedData.file_hash !== 'string';
  }

  isAdminAccountTargeted(mitreTechniques, normalizedData) {
    const adminTechniques = ['T1098', 'T1110', 'T1110.003'];
    const hasAdminTechnique = mitreTechniques.some(t => {
      const techniqueId = typeof t === 'string' ? t : t.id;
      return adminTechniques.includes(techniqueId);
    });
    
    return hasAdminTechnique && this.isPrivilegedAccount(normalizedData);
  }

  hasVPNSession(normalizedData) {
    return normalizedData.description && 
           normalizedData.description.toLowerCase().includes('vpn');
  }

  isNewCountry(normalizedData) {
    return normalizedData.description && 
           (normalizedData.description.toLowerCase().includes('new country') ||
            normalizedData.description.toLowerCase().includes('unusual location'));
  }

  isOutsideBusinessHours(normalizedData) {
    return normalizedData.description && 
           (normalizedData.description.toLowerCase().includes('business hours') ||
            normalizedData.description.toLowerCase().includes('after hours'));
  }

  calculateSeverityLevel(riskScore) {
    if (riskScore >= 85) return 'Critical';
    if (riskScore >= 65) return 'High';
    if (riskScore >= 45) return 'Medium';
    return 'Low';
  }

  getRiskLevel(riskScore) {
    const severity = this.calculateSeverityLevel(riskScore);
    return {
      score: riskScore,
      severity: severity,
      color: this.getRiskColor(severity),
      priority: this.getRiskPriority(severity)
    };
  }

  getRiskColor(severity) {
    const colors = {
      'Critical': '#DC2626',  // Red
      'High': '#EA580C',      // Orange
      'Medium': '#CA8A04',    // Yellow
      'Low': '#16A34A'        // Green
    };
    
    return colors[severity] || '#6B7280';  // Gray default
  }

  getRiskPriority(severity) {
    const priorities = {
      'Critical': 1,
      'High': 2,
      'Medium': 3,
      'Low': 4
    };
    
    return priorities[severity] || 5;
  }

  validateRiskModel(riskModel) {
    const errors = [];
    const warnings = [];
    
    if (!riskModel.base_severity) {
      errors.push('Base severity is required');
    }
    
    if (typeof riskModel.risk_score !== 'number' || riskModel.risk_score < 0 || riskModel.risk_score > 100) {
      errors.push('Risk score must be a number between 0 and 100');
    }
    
    if (!Array.isArray(riskModel.risk_adjustments)) {
      warnings.push('Risk adjustments should be an array');
    }
    
    riskModel.risk_adjustments.forEach(adjustment => {
      if (!adjustment.condition) {
        warnings.push('Risk adjustment missing condition');
      }
      if (typeof adjustment.add_score !== 'number') {
        warnings.push('Risk adjustment score should be a number');
      }
    });
    
    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }
}

module.exports = RiskCalculator;
