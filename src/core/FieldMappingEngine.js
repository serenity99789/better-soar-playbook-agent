const fs = require('fs-extra');
const path = require('path');

class FieldMappingEngine {
  constructor() {
    this.mappings = this.loadMappings();
  }

  loadMappings() {
    try {
      const mappingPath = path.join(__dirname, '../config/field_mappings.json');
      return fs.readJsonSync(mappingPath);
    } catch (error) {
      console.warn('Field mappings file not found, using defaults');
      return this.getDefaultMappings();
    }
  }

  getDefaultMappings() {
    return {
      "description": "Normalized SOC schema to platform field mapping",
      "version": "1.0",
      "platforms": {
        "splunk_cim": {
          "data_models": {
            "Authentication": {
              "normalized_to_cim": {
                "username": "user",
                "source_ip": "src",
                "destination_ip": "dest",
                "hostname": "dest_host",
                "app": "app",
                "authentication_method": "authentication_method",
                "authentication_result": "action",
                "failure_reason": "reason",
                "session_id": "session_id",
                "timestamp": "_time",
                "signature": "signature",
                "severity": "severity"
              }
            },
            "Endpoint.Processes": {
              "normalized_to_cim": {
                "hostname": "dest",
                "username": "user",
                "process_name": "process",
                "process_id": "process_id",
                "parent_process_name": "parent_process",
                "parent_process_id": "parent_process_id",
                "process_command_line": "process_command_line",
                "file_hash": "file_hash",
                "sha256": "file_hash",
                "md5": "file_hash",
                "process_path": "process_path",
                "timestamp": "_time",
                "action": "action"
              }
            },
            "Endpoint.Filesystem": {
              "normalized_to_cim": {
                "hostname": "dest",
                "username": "user",
                "file_name": "file_name",
                "file_path": "file_path",
                "file_hash": "file_hash",
                "file_size": "file_size",
                "file_action": "action",
                "timestamp": "_time"
              }
            },
            "Email": {
              "normalized_to_cim": {
                "sender_email": "src_user",
                "recipient_email": "dest_user",
                "source_ip": "src",
                "message_subject": "subject",
                "message_id": "message_id",
                "attachment_name": "file_name",
                "attachment_hash": "file_hash",
                "email_action": "action",
                "timestamp": "_time",
                "severity": "severity"
              }
            },
            "Web": {
              "normalized_to_cim": {
                "source_ip": "src",
                "destination_ip": "dest",
                "username": "user",
                "url": "url",
                "http_method": "http_method",
                "http_status": "status",
                "user_agent": "user_agent",
                "bytes_in": "bytes_in",
                "bytes_out": "bytes_out",
                "category": "category",
                "timestamp": "_time"
              }
            },
            "Network_Traffic": {
              "normalized_to_cim": {
                "source_ip": "src",
                "destination_ip": "dest",
                "source_port": "src_port",
                "destination_port": "dest_port",
                "protocol": "transport",
                "bytes_transferred": "bytes",
                "action": "action",
                "direction": "direction",
                "timestamp": "_time"
              }
            },
            "Malware": {
              "normalized_to_cim": {
                "hostname": "dest",
                "username": "user",
                "file_hash": "file_hash",
                "signature_name": "signature",
                "malware_name": "signature",
                "severity": "severity",
                "category": "category",
                "action": "action",
                "timestamp": "_time"
              }
            },
            "Intrusion_Detection": {
              "normalized_to_cim": {
                "source_ip": "src",
                "destination_ip": "dest",
                "signature_name": "signature",
                "signature_id": "signature_id",
                "severity": "severity",
                "attack_name": "signature",
                "category": "category",
                "timestamp": "_time",
                "action": "action"
              }
            }
          }
        },
        "google_udm": {
          "normalized_to_udm": {
            "source_ip": "principal.ip",
            "username": "principal.user.userid",
            "destination_ip": "target.ip",
            "hostname": "target.hostname",
            "file_hash": "target.file.sha256",
            "process_name": "target.process.file.name",
            "process_id": "target.process.pid",
            "parent_process_name": "target.process.parent_process.file.name",
            "process_command_line": "target.process.command_line",
            "url": "network.http.request_url",
            "http_method": "network.http.method",
            "http_status": "network.http.response_code",
            "user_agent": "network.http.user_agent",
            "sender_email": "email.from",
            "recipient_email": "email.to",
            "message_subject": "email.subject",
            "attachment_name": "email.attachments.file_name",
            "attachment_hash": "email.attachments.sha256",
            "timestamp": "metadata.event_timestamp",
            "severity": "metadata.event_type",
            "signature": "metadata.product_event_type"
          }
        }
      }
    };
  }

  getPlatformMappings(platform) {
    const platformKey = platform.toLowerCase();
    if (platformKey === 'splunk') {
      return this.mappings.platforms.splunk_cim;
    } else if (platformKey === 'google' || platformKey === 'chronicle') {
      return this.mappings.platforms.google_udm;
    }
    throw new Error(`Unsupported platform: ${platform}`);
  }

  mapFields(normalizedFields, platform, dataModel = null) {
    const platformMappings = this.getPlatformMappings(platform);
    const mappedFields = {};

    if (platform === 'splunk' && dataModel) {
      // Use specific data model mapping for Splunk
      const dataModelMapping = platformMappings.data_models[dataModel];
      if (dataModelMapping) {
        Object.keys(normalizedFields).forEach(field => {
          const mappedField = dataModelMapping.normalized_to_cim[field];
          if (mappedField) {
            mappedFields[mappedField] = normalizedFields[field];
          } else {
            mappedFields[field] = normalizedFields[field];
          }
        });
      }
    } else {
      // Use general mapping for other platforms
      const mappingKey = platform === 'splunk' ? 'data_models' : 'normalized_to_udm';
      const fieldMap = platform === 'splunk' ? 
        this.extractAllSplunkMappings(platformMappings) : 
        platformMappings[mappingKey];

      Object.keys(normalizedFields).forEach(field => {
        const mappedField = fieldMap[field];
        if (mappedField) {
          mappedFields[mappedField] = normalizedFields[field];
        } else {
          mappedFields[field] = normalizedFields[field];
        }
      });
    }

    return mappedFields;
  }

  extractAllSplunkMappings(splunkMappings) {
    const allMappings = {};
    Object.keys(splunkMappings.data_models).forEach(dataModel => {
      const modelMappings = splunkMappings.data_models[dataModel].normalized_to_cim;
      Object.assign(allMappings, modelMappings);
    });
    return allMappings;
  }

  reverseMapFields(platformFields, platform, dataModel = null) {
    const platformMappings = this.getPlatformMappings(platform);
    const normalizedFields = {};

    if (platform === 'splunk' && dataModel) {
      const dataModelMapping = platformMappings.data_models[dataModel];
      if (dataModelMapping) {
        const reverseMapping = this.invertMapping(dataModelMapping.normalized_to_cim);
        Object.keys(platformFields).forEach(field => {
          const normalizedField = reverseMapping[field];
          if (normalizedField) {
            normalizedFields[normalizedField] = platformFields[field];
          } else {
            normalizedFields[field] = platformFields[field];
          }
        });
      }
    } else {
      const mappingKey = platform === 'splunk' ? 'data_models' : 'normalized_to_udm';
      const fieldMap = platform === 'splunk' ? 
        this.extractAllSplunkMappings(platformMappings) : 
        platformMappings[mappingKey];

      const reverseMapping = this.invertMapping(fieldMap);
      Object.keys(platformFields).forEach(field => {
        const normalizedField = reverseMapping[field];
        if (normalizedField) {
          normalizedFields[normalizedField] = platformFields[field];
        } else {
          normalizedFields[field] = platformFields[field];
        }
      });
    }

    return normalizedFields;
  }

  invertMapping(mapping) {
    const inverted = {};
    Object.keys(mapping).forEach(key => {
      inverted[mapping[key]] = key;
    });
    return inverted;
  }

  validateMapping(normalizedField, platform, dataModel = null) {
    try {
      const platformMappings = this.getPlatformMappings(platform);
      
      if (platform === 'splunk' && dataModel) {
        const dataModelMapping = platformMappings.data_models[dataModel];
        return dataModelMapping && dataModelMapping.normalized_to_cim[normalizedField];
      } else {
        const mappingKey = platform === 'splunk' ? 'data_models' : 'normalized_to_udm';
        const fieldMap = platform === 'splunk' ? 
          this.extractAllSplunkMappings(platformMappings) : 
          platformMappings[mappingKey];
        return fieldMap[normalizedField];
      }
    } catch (error) {
      return false;
    }
  }

  getSupportedPlatforms() {
    return Object.keys(this.mappings.platforms);
  }

  getSupportedDataModels(platform) {
    if (platform.toLowerCase() === 'splunk') {
      return Object.keys(this.mappings.platforms.splunk_cim.data_models);
    }
    return [];
  }
}

module.exports = FieldMappingEngine;
