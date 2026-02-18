const fs = require('fs-extra');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

class InputProcessor {
  constructor() {
    this.supportedFormats = ['.txt', '.json', '.csv', '.log', '.irp'];
  }

  async processInput(input, type = 'text') {
    try {
      switch (type) {
        case 'text':
          return this.processText(input);
        case 'file':
          return this.processFile(input);
        case 'json':
          return this.processJSON(input);
        case 'csv':
          return this.processCSV(input);
        case 'irp':
          return this.processIRP(input);
        default:
          throw new Error(`Unsupported input type: ${type}`);
      }
    } catch (error) {
      throw new Error(`Input processing failed: ${error.message}`);
    }
  }

  processText(text) {
    if (!text || typeof text !== 'string') {
      throw new Error('Invalid text input');
    }

    // Extract key information from text
    const extracted = {
      id: uuidv4(),
      type: 'text',
      content: text,
      metadata: {
        length: text.length,
        wordCount: text.split(/\s+/).length,
        processedAt: new Date().toISOString()
      },
      extractedFields: this.extractFieldsFromText(text),
      normalizedData: this.normalizeTextData(text)
    };

    return extracted;
  }

  async processFile(filePath) {
    if (!await fs.pathExists(filePath)) {
      throw new Error('File does not exist');
    }

    const ext = path.extname(filePath).toLowerCase();
    
    if (!this.supportedFormats.includes(ext)) {
      throw new Error(`Unsupported file format: ${ext}`);
    }

    const content = await fs.readFile(filePath, 'utf8');
    const stats = await fs.stat(filePath);

    const processed = {
      id: uuidv4(),
      type: 'file',
      filePath: filePath,
      format: ext,
      content: content,
      metadata: {
        size: stats.size,
        createdAt: stats.birthtime,
        modifiedAt: stats.mtime,
        processedAt: new Date().toISOString()
      }
    };

    // Process based on file format
    switch (ext) {
      case '.json':
        return { ...processed, ...this.processJSON(content) };
      case '.csv':
        return { ...processed, ...this.processCSV(content) };
      case '.irp':
        return { ...processed, ...this.processIRP(content) };
      default:
        return { ...processed, ...this.processText(content) };
    }
  }

  processJSON(jsonContent) {
    try {
      const parsed = typeof jsonContent === 'string' ? JSON.parse(jsonContent) : jsonContent;
      
      return {
        format: 'json',
        data: parsed,
        extractedFields: this.extractFieldsFromJSON(parsed),
        normalizedData: this.normalizeJSONData(parsed)
      };
    } catch (error) {
      throw new Error(`Invalid JSON format: ${error.message}`);
    }
  }

  processCSV(csvContent) {
    const lines = csvContent.split('\n').filter(line => line.trim());
    if (lines.length === 0) {
      throw new Error('Empty CSV file');
    }

    const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
    const rows = lines.slice(1).map(line => {
      const values = line.split(',').map(v => v.trim().replace(/"/g, ''));
      const row = {};
      headers.forEach((header, index) => {
        row[header] = values[index] || '';
      });
      return row;
    });

    return {
      format: 'csv',
      headers: headers,
      rows: rows,
      extractedFields: this.extractFieldsFromCSV(headers, rows),
      normalizedData: this.normalizeCSVData(headers, rows)
    };
  }

  processIRP(irpContent) {
    // IRP (Incident Response Playbook) format processing
    try {
      // Try to parse as JSON first
      const parsed = JSON.parse(irpContent);
      return this.processJSON(parsed);
    } catch {
      // If not JSON, process as structured text
      return {
        format: 'irp',
        data: this.parseIRPText(irpContent),
        extractedFields: this.extractFieldsFromText(irpContent),
        normalizedData: this.normalizeTextData(irpContent)
      };
    }
  }

  parseIRPText(content) {
    const sections = {};
    const lines = content.split('\n');
    let currentSection = null;
    let currentContent = [];

    lines.forEach(line => {
      const trimmed = line.trim();
      
      // Detect section headers (e.g., "## Detection Logic", "### Response Actions")
      if (trimmed.startsWith('##') || trimmed.startsWith('###')) {
        if (currentSection) {
          sections[currentSection] = currentContent.join('\n').trim();
        }
        currentSection = trimmed.replace(/^#+\s*/, '');
        currentContent = [];
      } else if (trimmed) {
        currentContent.push(line);
      }
    });

    // Add the last section
    if (currentSection) {
      sections[currentSection] = currentContent.join('\n').trim();
    }

    return sections;
  }

  extractFieldsFromText(text) {
    const fields = {};
    
    // Common patterns for security data
    const patterns = {
      ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
      email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      hash: /\b[a-fA-F0-9]{32,64}\b/g,
      url: /https?:\/\/[^\s]+/g,
      username: /user(?:name)?:\s*([^\s,]+)/gi,
      domain: /\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b/g,
      timestamp: /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/g
    };

    Object.keys(patterns).forEach(key => {
      const matches = text.match(patterns[key]);
      if (matches) {
        fields[key] = [...new Set(matches)]; // Remove duplicates
      }
    });

    // Extract MITRE techniques
    const mitrePattern = /T\d{4}(?:\.\d{3})?/g;
    const mitreMatches = text.match(mitrePattern);
    if (mitreMatches) {
      fields.mitre_techniques = [...new Set(mitreMatches)];
    }

    return fields;
  }

  extractFieldsFromJSON(data) {
    const fields = {};
    
    function extractRecursive(obj, prefix = '') {
      if (typeof obj === 'object' && obj !== null) {
        Object.keys(obj).forEach(key => {
          const fullKey = prefix ? `${prefix}.${key}` : key;
          const value = obj[key];
          
          if (typeof value === 'string') {
            // Check for patterns in string values
            if (value.match(/^(?:\d{1,3}\.){3}\d{1,3}$/)) {
              fields.ip = fields.ip || [];
              fields.ip.push(value);
            } else if (value.match(/^[a-fA-F0-9]{32,64}$/)) {
              fields.hash = fields.hash || [];
              fields.hash.push(value);
            } else if (value.match(/^T\d{4}(?:\.\d{3})?$/)) {
              fields.mitre_techniques = fields.mitre_techniques || [];
              fields.mitre_techniques.push(value);
            }
          }
          
          extractRecursive(value, fullKey);
        });
      }
    }
    
    extractRecursive(data);
    
    // Remove duplicates
    Object.keys(fields).forEach(key => {
      fields[key] = [...new Set(fields[key])];
    });
    
    return fields;
  }

  extractFieldsFromCSV(headers, rows) {
    const fields = {};
    
    headers.forEach(header => {
      const lowerHeader = header.toLowerCase();
      
      rows.forEach(row => {
        const value = row[header];
        if (!value) return;
        
        if (lowerHeader.includes('ip') && value.match(/^(?:\d{1,3}\.){3}\d{1,3}$/)) {
          fields.ip = fields.ip || [];
          fields.ip.push(value);
        } else if (lowerHeader.includes('hash') && value.match(/^[a-fA-F0-9]{32,64}$/)) {
          fields.hash = fields.hash || [];
          fields.hash.push(value);
        } else if (lowerHeader.includes('email') && value.includes('@')) {
          fields.email = fields.email || [];
          fields.email.push(value);
        } else if (lowerHeader.includes('mitre') && value.match(/^T\d{4}(?:\.\d{3})?$/)) {
          fields.mitre_techniques = fields.mitre_techniques || [];
          fields.mitre_techniques.push(value);
        }
      });
    });
    
    // Remove duplicates
    Object.keys(fields).forEach(key => {
      fields[key] = [...new Set(fields[key])];
    });
    
    return fields;
  }

  normalizeTextData(text) {
    const normalized = {
      entity_type: 'unknown',
      source_ip: null,
      username: null,
      file_hash: null,
      url: null,
      timestamp: null,
      description: text.substring(0, 500) + (text.length > 500 ? '...' : '')
    };

    const fields = this.extractFieldsFromText(text);
    
    if (fields.ip && fields.ip.length > 0) {
      normalized.source_ip = fields.ip[0];
      normalized.entity_type = 'ip';
    }
    
    if (fields.email && fields.email.length > 0) {
      normalized.username = fields.email[0];
      normalized.entity_type = 'user';
    }
    
    if (fields.hash && fields.hash.length > 0) {
      normalized.file_hash = fields.hash[0];
      normalized.entity_type = 'file';
    }
    
    if (fields.url && fields.url.length > 0) {
      normalized.url = fields.url[0];
      normalized.entity_type = 'url';
    }
    
    if (fields.timestamp && fields.timestamp.length > 0) {
      normalized.timestamp = fields.timestamp[0];
    }

    return normalized;
  }

  normalizeJSONData(data) {
    const normalized = {
      entity_type: 'unknown',
      source_ip: null,
      username: null,
      file_hash: null,
      url: null,
      timestamp: null,
      description: JSON.stringify(data).substring(0, 500)
    };

    function findField(obj, fieldNames) {
      if (typeof obj !== 'object' || obj === null) return null;
      
      for (const name of fieldNames) {
        if (obj[name] !== undefined) {
          return obj[name];
        }
      }
      
      // Search recursively
      for (const key in obj) {
        const result = findField(obj[key], fieldNames);
        if (result) return result;
      }
      
      return null;
    }

    normalized.source_ip = findField(data, ['source_ip', 'src_ip', 'ip', 'src', 'client_ip']);
    normalized.username = findField(data, ['username', 'user', 'email', 'account']);
    normalized.file_hash = findField(data, ['file_hash', 'hash', 'sha256', 'md5']);
    normalized.url = findField(data, ['url', 'uri', 'link']);
    normalized.timestamp = findField(data, ['timestamp', 'time', 'date', '_time']);

    // Determine entity type
    if (normalized.username) normalized.entity_type = 'user';
    else if (normalized.source_ip) normalized.entity_type = 'ip';
    else if (normalized.file_hash) normalized.entity_type = 'file';
    else if (normalized.url) normalized.entity_type = 'url';

    return normalized;
  }

  normalizeCSVData(headers, rows) {
    const normalized = {
      entity_type: 'unknown',
      source_ip: null,
      username: null,
      file_hash: null,
      url: null,
      timestamp: null,
      description: `CSV with ${rows.length} rows and ${headers.length} columns`
    };

    // Find relevant columns
    const ipColumn = headers.find(h => h.toLowerCase().includes('ip'));
    const userColumn = headers.find(h => h.toLowerCase().includes('user') || h.toLowerCase().includes('email'));
    const hashColumn = headers.find(h => h.toLowerCase().includes('hash'));
    const urlColumn = headers.find(h => h.toLowerCase().includes('url'));
    const timeColumn = headers.find(h => h.toLowerCase().includes('time') || h.toLowerCase().includes('date'));

    if (rows.length > 0) {
      const firstRow = rows[0];
      normalized.source_ip = firstRow[ipColumn];
      normalized.username = firstRow[userColumn];
      normalized.file_hash = firstRow[hashColumn];
      normalized.url = firstRow[urlColumn];
      normalized.timestamp = firstRow[timeColumn];
    }

    // Determine entity type
    if (normalized.username) normalized.entity_type = 'user';
    else if (normalized.source_ip) normalized.entity_type = 'ip';
    else if (normalized.file_hash) normalized.entity_type = 'file';
    else if (normalized.url) normalized.entity_type = 'url';

    return normalized;
  }

  validateInput(input, type) {
    if (!input) {
      throw new Error('Input cannot be empty');
    }

    if (type === 'file' && !fs.existsSync(input)) {
      throw new Error('File does not exist');
    }

    return true;
  }
}

module.exports = InputProcessor;
