const { v4: uuidv4 } = require('uuid');
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');

class VersionControlEngine {
  constructor() {
    this.versions = new Map();
    this.branches = new Map();
    this.tags = new Map();
    this.auditTrail = [];
    this.storagePath = path.join(__dirname, '../data/versions');
    this.ensureStorageDirectory();
  }

  async ensureStorageDirectory() {
    await fs.ensureDir(this.storagePath);
  }

  async createVersion(playbook, changeDescription = '', author = 'system', branch = 'main') {
    try {
      const versionId = this.generateVersionId();
      const timestamp = new Date().toISOString();
      const checksum = this.calculateChecksum(playbook);
      
      // Create version object
      const version = {
        version_id: versionId,
        playbook_id: playbook.playbook_id,
        playbook_name: playbook.playbook_name,
        version_number: await this.getNextVersionNumber(playbook.playbook_id, branch),
        branch: branch,
        checksum: checksum,
        created_at: timestamp,
        created_by: author,
        change_description: changeDescription,
        parent_version: await this.getParentVersion(playbook.playbook_id, branch),
        playbook_snapshot: JSON.parse(JSON.stringify(playbook)), // Deep clone
        metadata: {
          size: JSON.stringify(playbook).length,
          platform: playbook.platform,
          category: playbook.use_case.use_case_metadata.category,
          severity: playbook.use_case.risk_model.base_severity,
          mitre_techniques: playbook.use_case.mitre_techniques,
          tags: playbook.metadata?.tags || []
        }
      };

      // Store version
      this.versions.set(versionId, version);
      
      // Update branch pointer
      this.branches.set(`${playbook.playbook_id}:${branch}`, versionId);
      
      // Persist to storage
      await this.persistVersion(version);
      
      // Add to audit trail
      this.addAuditEntry({
        action: 'create_version',
        version_id: versionId,
        playbook_id: playbook.playbook_id,
        author: author,
        timestamp: timestamp,
        description: changeDescription,
        checksum: checksum
      });

      return version;
    } catch (error) {
      throw new Error(`Version creation failed: ${error.message}`);
    }
  }

  async getNextVersionNumber(playbookId, branch) {
    const branchKey = `${playbookId}:${branch}`;
    const currentVersionId = this.branches.get(branchKey);
    
    if (!currentVersionId) {
      return '1.0.0';
    }
    
    const currentVersion = this.versions.get(currentVersionId);
    if (!currentVersion) {
      return '1.0.0';
    }
    
    // Simple semantic versioning increment
    const parts = currentVersion.version_number.split('.');
    parts[2] = (parseInt(parts[2]) + 1).toString();
    
    return parts.join('.');
  }

  async getParentVersion(playbookId, branch) {
    const branchKey = `${playbookId}:${branch}`;
    return this.branches.get(branchKey) || null;
  }

  generateVersionId() {
    return `v_${uuidv4().replace(/-/g, '_')}`;
  }

  calculateChecksum(playbook) {
    const playbookString = JSON.stringify(playbook, Object.keys(playbook).sort());
    return crypto.createHash('sha256').update(playbookString).digest('hex');
  }

  async persistVersion(version) {
    const versionFile = path.join(this.storagePath, `${version.version_id}.json`);
    await fs.writeJson(versionFile, version, { spaces: 2 });
  }

  async loadVersions() {
    try {
      const files = await fs.readdir(this.storagePath);
      const versionFiles = files.filter(file => file.endsWith('.json'));
      
      for (const file of versionFiles) {
        const versionPath = path.join(this.storagePath, file);
        const version = await fs.readJson(versionPath);
        this.versions.set(version.version_id, version);
        
        // Update branch pointers
        const branchKey = `${version.playbook_id}:${version.branch}`;
        this.branches.set(branchKey, version.version_id);
      }
      
      console.log(`Loaded ${this.versions.size} versions from storage`);
    } catch (error) {
      console.warn('Failed to load versions from storage:', error.message);
    }
  }

  getVersion(versionId) {
    return this.versions.get(versionId);
  }

  getLatestVersion(playbookId, branch = 'main') {
    const branchKey = `${playbookId}:${branch}`;
    const versionId = this.branches.get(branchKey);
    return versionId ? this.versions.get(versionId) : null;
  }

  getVersionHistory(playbookId, branch = null) {
    const versions = Array.from(this.versions.values())
      .filter(version => version.playbook_id === playbookId)
      .filter(version => !branch || version.branch === branch)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    
    return versions;
  }

  async createBranch(playbookId, branchName, fromVersionId, author = 'system') {
    try {
      const fromVersion = this.versions.get(fromVersionId);
      if (!fromVersion) {
        throw new Error('Source version not found');
      }

      if (fromVersion.playbook_id !== playbookId) {
        throw new Error('Source version does not belong to specified playbook');
      }

      const branchKey = `${playbookId}:${branchName}`;
      
      if (this.branches.has(branchKey)) {
        throw new Error(`Branch ${branchName} already exists`);
      }

      // Create branch by copying the version
      const branchVersion = {
        ...fromVersion,
        version_id: this.generateVersionId(),
        branch: branchName,
        created_at: new Date().toISOString(),
        created_by: author,
        change_description: `Created branch ${branchName} from version ${fromVersion.version_number}`,
        parent_version: fromVersionId
      };

      this.versions.set(branchVersion.version_id, branchVersion);
      this.branches.set(branchKey, branchVersion.version_id);
      
      await this.persistVersion(branchVersion);
      
      this.addAuditEntry({
        action: 'create_branch',
        version_id: branchVersion.version_id,
        playbook_id: playbookId,
        author: author,
        timestamp: branchVersion.created_at,
        description: `Created branch ${branchName}`,
        from_version: fromVersionId
      });

      return branchVersion;
    } catch (error) {
      throw new Error(`Branch creation failed: ${error.message}`);
    }
  }

  async mergeBranch(playbookId, sourceBranch, targetBranch = 'main', author = 'system') {
    try {
      const sourceBranchKey = `${playbookId}:${sourceBranch}`;
      const targetBranchKey = `${playbookId}:${targetBranch}`;
      
      const sourceVersionId = this.branches.get(sourceBranchKey);
      const targetVersionId = this.branches.get(targetBranchKey);
      
      if (!sourceVersionId) {
        throw new Error(`Source branch ${sourceBranch} not found`);
      }
      
      const sourceVersion = this.versions.get(sourceVersionId);
      
      // Create merge commit
      const mergeVersion = {
        ...sourceVersion,
        version_id: this.generateVersionId(),
        branch: targetBranch,
        created_at: new Date().toISOString(),
        created_by: author,
        change_description: `Merged branch ${sourceBranch} into ${targetBranch}`,
        parent_version: targetVersionId,
        merge_source: sourceVersionId
      };

      this.versions.set(mergeVersion.version_id, mergeVersion);
      this.branches.set(targetBranchKey, mergeVersion.version_id);
      
      // Remove source branch
      this.branches.delete(sourceBranchKey);
      
      await this.persistVersion(mergeVersion);
      
      this.addAuditEntry({
        action: 'merge_branch',
        version_id: mergeVersion.version_id,
        playbook_id: playbookId,
        author: author,
        timestamp: mergeVersion.created_at,
        description: `Merged ${sourceBranch} into ${targetBranch}`,
        source_branch: sourceBranch,
        target_branch: targetBranch
      });

      return mergeVersion;
    } catch (error) {
      throw new Error(`Branch merge failed: ${error.message}`);
    }
  }

  async createTag(playbookId, tagName, versionId, author = 'system', description = '') {
    try {
      const version = this.versions.get(versionId);
      if (!version) {
        throw new Error('Version not found');
      }

      if (version.playbook_id !== playbookId) {
        throw new Error('Version does not belong to specified playbook');
      }

      const tagKey = `${playbookId}:${tagName}`;
      
      if (this.tags.has(tagKey)) {
        throw new Error(`Tag ${tagName} already exists`);
      }

      const tag = {
        tag_id: uuidv4(),
        playbook_id: playbookId,
        tag_name: tagName,
        version_id: versionId,
        version_number: version.version_number,
        created_at: new Date().toISOString(),
        created_by: author,
        description: description
      };

      this.tags.set(tagKey, tag);
      
      this.addAuditEntry({
        action: 'create_tag',
        tag_id: tag.tag_id,
        playbook_id: playbookId,
        version_id: versionId,
        author: author,
        timestamp: tag.created_at,
        description: `Created tag ${tagName}`,
        tag_name: tagName
      });

      return tag;
    } catch (error) {
      throw new Error(`Tag creation failed: ${error.message}`);
    }
  }

  getTag(playbookId, tagName) {
    const tagKey = `${playbookId}:${tagName}`;
    return this.tags.get(tagKey);
  }

  getTags(playbookId) {
    return Array.from(this.tags.values())
      .filter(tag => tag.playbook_id === playbookId)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  }

  async compareVersions(versionId1, versionId2) {
    const version1 = this.versions.get(versionId1);
    const version2 = this.versions.get(versionId2);
    
    if (!version1 || !version2) {
      throw new Error('One or both versions not found');
    }

    const comparison = {
      version1: {
        id: version1.version_id,
        number: version1.version_number,
        created_at: version1.created_at,
        author: version1.created_by
      },
      version2: {
        id: version2.version_id,
        number: version2.version_number,
        created_at: version2.created_at,
        author: version2.created_by
      },
      changes: this.detectChanges(version1.playbook_snapshot, version2.playbook_snapshot),
      metadata_changes: this.detectChanges(version1.metadata, version2.metadata)
    };

    return comparison;
  }

  detectChanges(obj1, obj2) {
    const changes = {
      added: [],
      modified: [],
      removed: []
    };

    const keys1 = new Set(Object.keys(obj1));
    const keys2 = new Set(Object.keys(obj2));

    // Find added keys
    for (const key of keys2) {
      if (!keys1.has(key)) {
        changes.added.push({
          key: key,
          value: obj2[key]
        });
      }
    }

    // Find removed keys
    for (const key of keys1) {
      if (!keys2.has(key)) {
        changes.removed.push({
          key: key,
          value: obj1[key]
        });
      }
    }

    // Find modified keys
    for (const key of keys1) {
      if (keys2.has(key) && JSON.stringify(obj1[key]) !== JSON.stringify(obj2[key])) {
        changes.modified.push({
          key: key,
          old_value: obj1[key],
          new_value: obj2[key]
        });
      }
    }

    return changes;
  }

  async rollbackToVersion(playbookId, versionId, author = 'system', reason = '') {
    try {
      const targetVersion = this.versions.get(versionId);
      if (!targetVersion) {
        throw new Error('Target version not found');
      }

      if (targetVersion.playbook_id !== playbookId) {
        throw new Error('Version does not belong to specified playbook');
      }

      // Create rollback version
      const rollbackVersion = {
        ...targetVersion,
        version_id: this.generateVersionId(),
        version_number: await this.getNextVersionNumber(playbookId, targetVersion.branch),
        created_at: new Date().toISOString(),
        created_by: author,
        change_description: `Rollback to version ${targetVersion.version_number}${reason ? ': ' + reason : ''}`,
        parent_version: this.branches.get(`${playbookId}:${targetVersion.branch}`),
        rollback_from: versionId
      };

      this.versions.set(rollbackVersion.version_id, rollbackVersion);
      this.branches.set(`${playbookId}:${rollbackVersion.branch}`, rollbackVersion.version_id);
      
      await this.persistVersion(rollbackVersion);
      
      this.addAuditEntry({
        action: 'rollback',
        version_id: rollbackVersion.version_id,
        playbook_id: playbookId,
        author: author,
        timestamp: rollbackVersion.created_at,
        description: `Rollback to version ${targetVersion.version_number}`,
        rollback_to: versionId,
        reason: reason
      });

      return rollbackVersion;
    } catch (error) {
      throw new Error(`Rollback failed: ${error.message}`);
    }
  }

  addAuditEntry(entry) {
    const auditEntry = {
      ...entry,
      audit_id: uuidv4(),
      timestamp: entry.timestamp || new Date().toISOString()
    };
    
    this.auditTrail.push(auditEntry);
    
    // Keep audit trail size manageable
    if (this.auditTrail.length > 10000) {
      this.auditTrail = this.auditTrail.slice(-5000);
    }
  }

  getAuditTrail(playbookId = null, action = null, limit = 100) {
    let filtered = this.auditTrail;
    
    if (playbookId) {
      filtered = filtered.filter(entry => entry.playbook_id === playbookId);
    }
    
    if (action) {
      filtered = filtered.filter(entry => entry.action === action);
    }
    
    return filtered
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, limit);
  }

  getVersionStats(playbookId) {
    const versions = Array.from(this.versions.values())
      .filter(version => version.playbook_id === playbookId);
    
    const branches = new Set(versions.map(v => v.branch));
    const authors = new Set(versions.map(v => v.created_by));
    
    return {
      total_versions: versions.length,
      branches: Array.from(branches),
      authors: Array.from(authors),
      latest_version: versions.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0],
      first_version: versions.sort((a, b) => new Date(a.created_at) - new Date(b.created_at))[0],
      tags: this.getTags(playbookId).length
    };
  }

  async exportVersionHistory(playbookId, format = 'json') {
    const versions = this.getVersionHistory(playbookId);
    const auditTrail = this.getAuditTrail(playbookId);
    const tags = this.getTags(playbookId);
    
    const exportData = {
      playbook_id: playbookId,
      exported_at: new Date().toISOString(),
      versions: versions,
      tags: tags,
      audit_trail: auditTrail,
      stats: this.getVersionStats(playbookId)
    };

    switch (format.toLowerCase()) {
      case 'json':
        return JSON.stringify(exportData, null, 2);
      case 'csv':
        return this.convertToCSV(exportData);
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  convertToCSV(data) {
    const csvLines = [];
    
    // Versions CSV
    csvLines.push('Type,ID,Playbook ID,Version,Branch,Created At,Created By,Description');
    data.versions.forEach(version => {
      csvLines.push([
        'Version',
        version.version_id,
        version.playbook_id,
        version.version_number,
        version.branch,
        version.created_at,
        version.created_by,
        `"${version.change_description}"`
      ].join(','));
    });
    
    // Tags CSV
    csvLines.push('Type,Tag ID,Playbook ID,Tag Name,Version,Created At,Created By');
    data.tags.forEach(tag => {
      csvLines.push([
        'Tag',
        tag.tag_id,
        tag.playbook_id,
        tag.tag_name,
        tag.version_number,
        tag.created_at,
        tag.created_by
      ].join(','));
    });
    
    return csvLines.join('\n');
  }

  async cleanupOldVersions(playbookId, keepCount = 10) {
    const versions = this.getVersionHistory(playbookId);
    
    if (versions.length <= keepCount) {
      return { deleted: 0 };
    }
    
    const versionsToDelete = versions.slice(keepCount);
    let deletedCount = 0;
    
    for (const version of versionsToDelete) {
      try {
        // Don't delete if it's tagged or current branch head
        const isTagged = this.getTags(playbookId).some(tag => tag.version_id === version.version_id);
        const isBranchHead = Array.from(this.branches.values()).includes(version.version_id);
        
        if (!isTagged && !isBranchHead) {
          this.versions.delete(version.version_id);
          
          // Delete file
          const versionFile = path.join(this.storagePath, `${version.version_id}.json`);
          await fs.remove(versionFile);
          
          deletedCount++;
        }
      } catch (error) {
        console.warn(`Failed to delete version ${version.version_id}:`, error.message);
      }
    }
    
    this.addAuditEntry({
      action: 'cleanup_versions',
      playbook_id: playbookId,
      author: 'system',
      timestamp: new Date().toISOString(),
      description: `Cleaned up ${deletedCount} old versions`,
      deleted_count: deletedCount
    });
    
    return { deleted: deletedCount };
  }
}

module.exports = VersionControlEngine;
