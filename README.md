# 🛡️ SOAR Playbook Generator Platform

An AI-powered Security Orchestration, Automation, and Response (SOAR) playbook generation platform with MITRE ATT&CK mapping and reverse query capabilities.

## 🚀 Features

### Core Capabilities
- **Multi-Input Support**: Process text descriptions, file uploads (.txt, .json, .csv, .log, .irp)
- **MITRE ATT&CK Integration**: Automatic mapping to relevant MITRE techniques
- **Platform-Specific Queries**: Generate queries for Splunk CIM and Google SecOps (Chronicle UDM)
- **Reverse Query Search**: Find existing playbooks based on query patterns
- **Risk-Based Scoring**: Dynamic risk calculation with adjustable factors
- **Approval Gating**: Configurable approval workflows for high-risk actions
- **Version Control**: Complete audit trail with branching and rollback capabilities

### Security Features
- **Field Mapping Engine**: Normalized schema to platform-specific field mapping
- **Asset Criticality Awareness**: Context-aware response based on asset importance
- **Business Hours Enforcement**: Time-based approval requirements
- **Privileged Account Detection**: Enhanced controls for admin account actions

### Enterprise Features
- **Audit Trail**: Complete change tracking and compliance reporting
- **Export Capabilities**: JSON, Markdown, and CSV export formats
- **Template Library**: Pre-built templates for common security scenarios
- **API-First Design**: RESTful API for integration with existing systems

## 📋 Prerequisites

- Node.js 16.x or higher
- npm 8.x or higher
- 4GB RAM minimum
- 2GB disk space

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd better-soar-playbook-agent
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Build the Frontend
```bash
npm run build:client
```

### 4. Start the Application
```bash
# Development mode
npm run dev

# Production mode
npm start
```

The application will be available at:
- Frontend: http://localhost:8080 (development) or http://localhost:3000 (production)
- API: http://localhost:3000

## 📖 Usage

### Web Interface

1. **Generate Playbook**
   - Navigate to the "Generate Playbook" tab
   - Choose input type (Text or File Upload)
   - Select target platform (Splunk or Chronicle)
   - Optionally specify category and severity
   - Click "Generate Playbook"

2. **Reverse Query Search**
   - Go to the "Reverse Query Search" tab
   - Enter your existing query
   - Select platform and apply filters
   - Review matching playbooks and relevance scores

3. **Browse Templates**
   - View pre-built templates in the "Templates" tab
   - Filter by category (Identity, Malware, Phishing, Network)
   - Review MITRE techniques and data sources

### API Usage

#### Generate Playbook from Text
```bash
curl -X POST http://localhost:3000/api/playbook/generate/text \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Multiple failed logins from IP 192.168.1.100 followed by successful login for admin@company.com",
    "platform": "splunk",
    "options": {
      "category": "identity",
      "severity": "high"
    }
  }'
```

#### Generate Playbook from File
```bash
curl -X POST http://localhost:3000/api/playbook/generate/file \
  -F "file=@security_log.json" \
  -F "platform=chronicle" \
  -F 'options={"category": "malware"}'
```

#### Reverse Query Search
```bash
curl -X POST http://localhost:3000/api/playbook/reverse-search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "| tstats count from datamodel=Authentication where Authentication.action=failure",
    "platform": "splunk",
    "filters": {
      "category": "identity",
      "severity": "high"
    }
  }'
```

## 🏗️ Architecture

### Core Components

1. **InputProcessor**: Handles various input formats and extracts security entities
2. **MITREMapper**: Maps security events to MITRE ATT&CK techniques
3. **FieldMappingEngine**: Translates normalized fields to platform-specific formats
4. **QueryGenerator**: Creates platform-specific detection and response queries
5. **PlaybookGenerator**: Orchestrates the complete playbook generation process
6. **ReverseQueryEngine**: Enables playbook discovery based on query patterns
7. **ApprovalGateEngine**: Manages approval workflows and risk-based gating
8. **VersionControlEngine**: Provides versioning, branching, and audit capabilities

### Data Flow

```
Input → Processing → MITRE Mapping → Field Mapping → Query Generation → Playbook Assembly → Approval → Version Control
```

## 🔧 Configuration

### Field Mappings
Edit `src/config/field_mappings.json` to customize platform-specific field mappings.

### MITRE Techniques
Update `src/config/mitre_techniques.json` to add or modify MITRE technique definitions.

### Approval Gates
Configure approval requirements in `src/config/approval_config.json`:
- Risk score thresholds
- Privileged account patterns
- Business hours settings
- Approver levels

## 📊 Supported Platforms

### Splunk (CIM)
- Authentication data model
- Endpoint data models (Processes, Filesystem)
- Network Traffic data model
- Email data model
- Web data model
- Malware data model
- Intrusion Detection data model

### Google SecOps (Chronicle UDM)
- Principal and target entity mapping
- Network event processing
- Process execution tracking
- File activity monitoring
- Email event handling

## 🎯 Use Cases

### Identity Security
- Brute force attack detection
- Password spray attacks
- Impossible travel scenarios
- MFA fatigue attacks
- Privilege escalation

### Malware Detection
- Known malware hash detection
- Suspicious PowerShell execution
- File-based indicators
- Process injection detection

### Phishing Prevention
- Email attachment analysis
- Malicious URL detection
- Credential harvesting
- Service-based phishing

### Network Security
- Command and control detection
- Lateral movement tracking
- Data exfiltration
- Anomalous traffic patterns

## 🔍 API Reference

### Playbook Generation
- `POST /api/playbook/generate/text` - Generate from text input
- `POST /api/playbook/generate/file` - Generate from file upload
- `POST /api/playbook/validate` - Validate playbook schema
- `POST /api/playbook/export` - Export playbook in various formats

### Reverse Search
- `POST /api/playbook/reverse-search` - Search for matching playbooks

### Version Control
- `POST /api/playbook/:id/version` - Create new version
- `GET /api/playbook/:id/versions` - Get version history
- `GET /api/playbook/:id/version/:versionId` - Get specific version
- `POST /api/playbook/:id/compare/:v1/:v2` - Compare versions
- `POST /api/playbook/:id/branch` - Create branch
- `POST /api/playbook/:id/merge` - Merge branch
- `POST /api/playbook/:id/rollback` - Rollback to version

### Approval Gates
- `POST /api/playbook/:id/approval/evaluate` - Evaluate approval requirements
- `GET /api/approval/:id` - Get approval request
- `POST /api/approval/:id/approve` - Approve request
- `POST /api/approval/:id/reject` - Reject request
- `GET /api/approvals/pending` - Get pending approvals

### Reference Data
- `GET /api/mitre/techniques` - Get MITRE techniques
- `GET /api/field-mappings/:platform` - Get field mappings
- `GET /api/templates/use-cases` - Get use case templates

## 🧪 Testing

### Run Tests
```bash
npm test
```

### Sample Data
Sample security logs and test files are available in the `samples/` directory:
- `samples/brute_force_log.json` - Brute force attack example
- `samples/malware_detection.csv` - Malware detection data
- `samples/phishing_email.irp` - Phishing IRP format

## 🔒 Security Considerations

### Input Validation
- All inputs are validated and sanitized
- File uploads are restricted to approved formats
- Rate limiting prevents abuse

### Data Protection
- No sensitive data is logged
- Temporary files are automatically cleaned
- Audit trail maintains compliance

### Access Control
- Configurable approval workflows
- Role-based permissions
- Business hours enforcement

## 🚀 Deployment

### Docker Deployment
```bash
# Build image
docker build -t soar-playbook-generator .

# Run container
docker run -p 3000:3000 soar-playbook-generator
```

### Environment Variables
- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment mode (development/production)
- `UPLOAD_DIR` - File upload directory (default: ./uploads)

## 📈 Monitoring

### Health Check
```bash
curl http://localhost:3000/api/health
```

### Metrics
The application provides built-in metrics for:
- Playbook generation success rates
- Approval processing times
- Version control statistics
- API response times

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Review the API documentation
- Check the sample configurations

## 🔄 Version History

### v1.0.0
- Initial release
- Core playbook generation functionality
- MITRE ATT&CK integration
- Splunk and Chronicle support
- Version control and approval gating
- Web interface and REST API

---

**Built with ❤️ for the Security Community**
