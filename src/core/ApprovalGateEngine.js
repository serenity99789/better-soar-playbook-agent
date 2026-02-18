const { v4: uuidv4 } = require('uuid');
const fs = require('fs-extra');
const path = require('path');

class ApprovalGateEngine {
  constructor() {
    this.approvalStore = new Map();
    this.approvalConfig = this.loadApprovalConfig();
    this.approvalHistory = [];
  }

  loadApprovalConfig() {
    try {
      const configPath = path.join(__dirname, '../config/approval_config.json');
      return fs.readJsonSync(configPath);
    } catch (error) {
      console.warn('Approval config file not found, using defaults');
      return this.getDefaultApprovalConfig();
    }
  }

  getDefaultApprovalConfig() {
    return {
      "approval_required_for": {
        "privileged_accounts": true,
        "critical_assets": true,
        "high_risk_score": 80,
        "certain_techniques": ["T1098", "T1110", "T1110.003"],
        "certain_actions": ["isolate_host", "block_source_ip", "disable_account"],
        "business_hours": {
          "enabled": true,
          "start_hour": 9,
          "end_hour": 17,
          "timezone": "UTC"
        }
      },
      "approvers": {
        "level_1": ["security_analyst", "team_lead"],
        "level_2": ["security_manager", "incident_commander"],
        "level_3": ["ciso", "director_security"]
      },
      "escalation": {
        "auto_approve_after": 24, // hours
        "escalate_after": 4, // hours
        "max_approval_time": 48 // hours
      },
      "notifications": {
        "email_enabled": true,
        "slack_enabled": true,
        "teams_enabled": false
      }
    };
  }

  async evaluateApprovalGates(playbook, executionContext = {}) {
    const approvalDecision = {
      requires_approval: false,
      approval_level: null,
      gates_triggered: [],
      auto_approve: false,
      reason: '',
      approval_id: null,
      expires_at: null
    };

    try {
      // Check various approval gates
      const gates = [
        this.checkPrivilegedAccountGate(playbook),
        this.checkCriticalAssetGate(playbook),
        this.checkRiskScoreGate(playbook),
        this.checkTechniqueGate(playbook),
        this.checkActionGate(playbook),
        this.checkBusinessHoursGate(playbook, executionContext),
        this.checkAssetCriticalityGate(playbook)
      ];

      // Evaluate all gates
      for (const gate of gates) {
        if (gate.triggered) {
          approvalDecision.requires_approval = true;
          approvalDecision.gates_triggered.push(gate);
          
          // Determine approval level based on gate severity
          if (gate.approval_level && (!approvalDecision.approval_level || 
              this.getApprovalLevelPriority(gate.approval_level) > 
              this.getApprovalLevelPriority(approvalDecision.approval_level))) {
            approvalDecision.approval_level = gate.approval_level;
          }
        }
      }

      // Set approval reason
      if (approvalDecision.requires_approval) {
        approvalDecision.reason = this.generateApprovalReason(approvalDecision.gates_triggered);
        approvalDecision.approval_id = uuidv4();
        approvalDecision.expires_at = this.calculateExpirationTime();
        
        // Create approval request
        await this.createApprovalRequest(approvalDecision, playbook, executionContext);
      } else {
        approvalDecision.reason = 'No approval gates triggered';
        approvalDecision.auto_approve = true;
      }

      return approvalDecision;
    } catch (error) {
      throw new Error(`Approval gate evaluation failed: ${error.message}`);
    }
  }

  checkPrivilegedAccountGate(playbook) {
    const gate = {
      name: 'privileged_account',
      triggered: false,
      approval_level: 'level_1',
      reason: ''
    };

    const normalizedFields = playbook.use_case.normalized_fields;
    const username = normalizedFields.username;
    
    if (username && this.isPrivilegedAccount(username)) {
      gate.triggered = true;
      gate.reason = `Privileged account detected: ${username}`;
      gate.approval_level = this.isHighlyPrivileged(username) ? 'level_2' : 'level_1';
    }

    return gate;
  }

  checkCriticalAssetGate(playbook) {
    const gate = {
      name: 'critical_asset',
      triggered: false,
      approval_level: 'level_2',
      reason: ''
    };

    const normalizedFields = playbook.use_case.normalized_fields;
    const hostname = normalizedFields.hostname;
    
    if (hostname && this.isCriticalAsset(hostname)) {
      gate.triggered = true;
      gate.reason = `Critical asset detected: ${hostname}`;
      gate.approval_level = this.isHighlyCriticalAsset(hostname) ? 'level_3' : 'level_2';
    }

    return gate;
  }

  checkRiskScoreGate(playbook) {
    const gate = {
      name: 'risk_score',
      triggered: false,
      approval_level: 'level_1',
      reason: ''
    };

    const riskScore = playbook.use_case.risk_model.risk_score;
    const threshold = this.approvalConfig.approval_required_for.high_risk_score;
    
    if (riskScore >= threshold) {
      gate.triggered = true;
      gate.reason = `High risk score: ${riskScore} (threshold: ${threshold})`;
      gate.approval_level = riskScore >= 90 ? 'level_2' : 'level_1';
    }

    return gate;
  }

  checkTechniqueGate(playbook) {
    const gate = {
      name: 'technique',
      triggered: false,
      approval_level: 'level_1',
      reason: ''
    };

    const techniques = playbook.use_case.mitre_techniques;
    const restrictedTechniques = this.approvalConfig.approval_required_for.certain_techniques;
    
    const matchingTechniques = techniques.filter(tech => restrictedTechniques.includes(tech));
    
    if (matchingTechniques.length > 0) {
      gate.triggered = true;
      gate.reason = `Restricted MITRE techniques: ${matchingTechniques.join(', ')}`;
      gate.approval_level = this.hasHighRiskTechniques(matchingTechniques) ? 'level_2' : 'level_1';
    }

    return gate;
  }

  checkActionGate(playbook) {
    const gate = {
      name: 'action',
      triggered: false,
      approval_level: 'level_1',
      reason: ''
    };

    const actions = playbook.actions?.automated_actions || [];
    const restrictedActions = this.approvalConfig.approval_required_for.certain_actions;
    
    const matchingActions = actions.filter(action => restrictedActions.includes(action));
    
    if (matchingActions.length > 0) {
      gate.triggered = true;
      gate.reason = `Restricted actions: ${matchingActions.join(', ')}`;
      gate.approval_level = this.hasHighRiskActions(matchingActions) ? 'level_2' : 'level_1';
    }

    return gate;
  }

  checkBusinessHoursGate(playbook, executionContext) {
    const gate = {
      name: 'business_hours',
      triggered: false,
      approval_level: 'level_1',
      reason: ''
    };

    const config = this.approvalConfig.approval_required_for.business_hours;
    
    if (config.enabled && !this.isBusinessHours(config)) {
      gate.triggered = true;
      gate.reason = 'Execution outside business hours';
      gate.approval_level = 'level_1';
    }

    return gate;
  }

  checkAssetCriticalityGate(playbook) {
    const gate = {
      name: 'asset_criticality',
      triggered: false,
      approval_level: 'level_1',
      reason: ''
    };

    const assetContext = playbook.use_case.asset_context;
    
    if (assetContext?.asset_criticality_aware) {
      // Check if asset criticality is explicitly set to high
      const riskAdjustments = playbook.use_case.risk_model.risk_adjustments || [];
      const highCriticalityAdjustment = riskAdjustments.find(adj => 
        adj.condition === 'high_critical_asset' || adj.condition === 'server_host'
      );
      
      if (highCriticalityAdjustment) {
        gate.triggered = true;
        gate.reason = 'High criticality asset involved';
        gate.approval_level = highCriticalityAdjustment.add_score >= 30 ? 'level_2' : 'level_1';
      }
    }

    return gate;
  }

  isPrivilegedAccount(username) {
    const privilegedPatterns = [
      /admin/i,
      /administrator/i,
      /root/i,
      /sa$/i,
      /service/i,
      /privileged/i,
      /elevated/i,
      /sudo/i,
      /domain.*admin/i,
      /enterprise.*admin/i
    ];
    
    return privilegedPatterns.some(pattern => pattern.test(username));
  }

  isHighlyPrivileged(username) {
    const highPrivilegePatterns = [
      /domain.*admin/i,
      /enterprise.*admin/i,
      /ciso/i,
      /security.*admin/i
    ];
    
    return highPrivilegePatterns.some(pattern => pattern.test(username));
  }

  isCriticalAsset(hostname) {
    const criticalPatterns = [
      /dc\d*/i,  // Domain controllers
      /domain.*controller/i,
      /ad.*server/i,
      /database/i,
      /db.*server/i,
      /production/i,
      /finance/i,
      /hr/i,
      /executive/i,
      /critical/i
    ];
    
    return criticalPatterns.some(pattern => pattern.test(hostname));
  }

  isHighlyCriticalAsset(hostname) {
    const highlyCriticalPatterns = [
      /dc\d*/i,  // Domain controllers
      /domain.*controller/i,
      /production.*db/i,
      /finance.*db/i
    ];
    
    return highlyCriticalPatterns.some(pattern => pattern.test(hostname));
  }

  hasHighRiskTechniques(techniques) {
    const highRiskTechniques = ['T1098', 'T1110'];
    return techniques.some(tech => highRiskTechniques.includes(tech));
  }

  hasHighRiskActions(actions) {
    const highRiskActions = ['isolate_host', 'disable_account'];
    return actions.some(action => highRiskActions.includes(action));
  }

  isBusinessHours(config) {
    const now = new Date();
    const currentHour = now.getHours();
    
    return currentHour >= config.start_hour && currentHour < config.end_hour;
  }

  getApprovalLevelPriority(level) {
    const priorities = {
      'level_1': 1,
      'level_2': 2,
      'level_3': 3
    };
    return priorities[level] || 0;
  }

  generateApprovalReason(gates) {
    const reasons = gates.map(gate => gate.reason);
    return `Approval required: ${reasons.join('; ')}`;
  }

  calculateExpirationTime() {
    const maxApprovalTime = this.approvalConfig.escalation.max_approval_time;
    const expiration = new Date();
    expiration.setHours(expiration.getHours() + maxApprovalTime);
    return expiration.toISOString();
  }

  async createApprovalRequest(approvalDecision, playbook, executionContext) {
    const approvalRequest = {
      approval_id: approvalDecision.approval_id,
      playbook_id: playbook.playbook_id,
      playbook_name: playbook.playbook_name,
      approval_level: approvalDecision.approval_level,
      gates_triggered: approvalDecision.gates_triggered,
      reason: approvalDecision.reason,
      status: 'pending',
      created_at: new Date().toISOString(),
      expires_at: approvalDecision.expires_at,
      requested_by: executionContext.user || 'system',
      execution_context: executionContext,
      playbook_summary: this.createPlaybookSummary(playbook),
      approvers: this.getApproversForLevel(approvalDecision.approval_level),
      notifications_sent: false
    };

    this.approvalStore.set(approvalDecision.approval_id, approvalRequest);
    
    // Send notifications if enabled
    if (this.shouldSendNotifications()) {
      await this.sendApprovalNotifications(approvalRequest);
    }

    return approvalRequest;
  }

  createPlaybookSummary(playbook) {
    return {
      name: playbook.playbook_name,
      category: playbook.use_case.use_case_metadata.category,
      severity: playbook.use_case.risk_model.base_severity,
      risk_score: playbook.use_case.risk_model.risk_score,
      techniques: playbook.use_case.mitre_techniques,
      actions: playbook.actions?.automated_actions || []
    };
  }

  getApproversForLevel(level) {
    return this.approvalConfig.approvers[level] || [];
  }

  shouldSendNotifications() {
    return this.approvalConfig.notifications.email_enabled || 
           this.approvalConfig.notifications.slack_enabled;
  }

  async sendApprovalNotifications(approvalRequest) {
    // Implementation would depend on notification systems
    console.log(`Approval notification sent for ${approvalRequest.approval_id}`);
    
    // Update notification status
    const request = this.approvalStore.get(approvalRequest.approval_id);
    if (request) {
      request.notifications_sent = true;
      this.approvalStore.set(approvalRequest.approval_id, request);
    }
  }

  async approveRequest(approvalId, approver, comments = '') {
    const request = this.approvalStore.get(approvalId);
    
    if (!request) {
      throw new Error('Approval request not found');
    }

    if (request.status !== 'pending') {
      throw new Error(`Approval request is ${request.status}, cannot approve`);
    }

    if (!this.isValidApprover(approver, request.approval_level)) {
      throw new Error('User is not authorized to approve this request');
    }

    // Update request
    request.status = 'approved';
    request.approved_by = approver;
    request.approved_at = new Date().toISOString();
    request.approval_comments = comments;
    
    this.approvalStore.set(approvalId, request);
    
    // Add to history
    this.approvalHistory.push({
      action: 'approve',
      approval_id: approvalId,
      approver: approver,
      timestamp: request.approved_at,
      comments: comments
    });

    return request;
  }

  async rejectRequest(approvalId, approver, reason) {
    const request = this.approvalStore.get(approvalId);
    
    if (!request) {
      throw new Error('Approval request not found');
    }

    if (request.status !== 'pending') {
      throw new Error(`Approval request is ${request.status}, cannot reject`);
    }

    if (!this.isValidApprover(approver, request.approval_level)) {
      throw new Error('User is not authorized to reject this request');
    }

    // Update request
    request.status = 'rejected';
    request.rejected_by = approver;
    request.rejected_at = new Date().toISOString();
    request.rejection_reason = reason;
    
    this.approvalStore.set(approvalId, request);
    
    // Add to history
    this.approvalHistory.push({
      action: 'reject',
      approval_id: approvalId,
      approver: approver,
      timestamp: request.rejected_at,
      reason: reason
    });

    return request;
  }

  isValidApprover(approver, requiredLevel) {
    const approvers = this.getApproversForLevel(requiredLevel);
    return approvers.includes(approver);
  }

  getApprovalRequest(approvalId) {
    return this.approvalStore.get(approvalId);
  }

  getPendingApprovals(user = null) {
    const pending = Array.from(this.approvalStore.values())
      .filter(request => request.status === 'pending');
    
    if (user) {
      return pending.filter(request => 
        this.isValidApprover(user, request.approval_level)
      );
    }
    
    return pending;
  }

  getApprovalHistory(approvalId = null) {
    if (approvalId) {
      return this.approvalHistory.filter(entry => entry.approval_id === approvalId);
    }
    return this.approvalHistory;
  }

  async checkExpiredApprovals() {
    const now = new Date();
    const expired = [];
    
    for (const [approvalId, request] of this.approvalStore.entries()) {
      if (request.status === 'pending' && new Date(request.expires_at) < now) {
        request.status = 'expired';
        request.expired_at = now.toISOString();
        this.approvalStore.set(approvalId, request);
        expired.push(request);
      }
    }
    
    return expired;
  }

  async escalatePendingApprovals() {
    const now = new Date();
    const escalateAfter = this.approvalConfig.escalation.escalate_after * 60 * 60 * 1000; // Convert to milliseconds
    const escalated = [];
    
    for (const [approvalId, request] of this.approvalStore.entries()) {
      if (request.status === 'pending') {
        const createdTime = new Date(request.created_at);
        if (now - createdTime > escalateAfter) {
          // Escalate to next level
          const nextLevel = this.getNextApprovalLevel(request.approval_level);
          if (nextLevel) {
            request.approval_level = nextLevel;
            request.escalated_at = now.toISOString();
            request.approvers = this.getApproversForLevel(nextLevel);
            this.approvalStore.set(approvalId, request);
            escalated.push(request);
          }
        }
      }
    }
    
    return escalated;
  }

  getNextApprovalLevel(currentLevel) {
    const levels = ['level_1', 'level_2', 'level_3'];
    const currentIndex = levels.indexOf(currentLevel);
    return currentIndex < levels.length - 1 ? levels[currentIndex + 1] : null;
  }

  getApprovalStats() {
    const requests = Array.from(this.approvalStore.values());
    
    return {
      total: requests.length,
      pending: requests.filter(r => r.status === 'pending').length,
      approved: requests.filter(r => r.status === 'approved').length,
      rejected: requests.filter(r => r.status === 'rejected').length,
      expired: requests.filter(r => r.status === 'expired').length,
      average_approval_time: this.calculateAverageApprovalTime()
    };
  }

  calculateAverageApprovalTime() {
    const approved = Array.from(this.approvalStore.values())
      .filter(r => r.status === 'approved' && r.approved_at);
    
    if (approved.length === 0) return 0;
    
    const totalTime = approved.reduce((sum, request) => {
      const created = new Date(request.created_at);
      const approved = new Date(request.approved_at);
      return sum + (approved - created);
    }, 0);
    
    return Math.round(totalTime / approved.length / (1000 * 60)); // Convert to minutes
  }
}

module.exports = ApprovalGateEngine;
