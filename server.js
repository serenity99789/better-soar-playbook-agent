const express = require('express');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs-extra');
const { v4: uuidv4 } = require('uuid');

const PlaybookGenerator = require('./src/core/PlaybookGenerator');
const FieldMappingEngine = require('./src/core/FieldMappingEngine');
const MITREMapper = require('./src/core/MITREMapper');
const ReverseQueryEngine = require('./src/core/ReverseQueryEngine');
const ApprovalGateEngine = require('./src/core/ApprovalGateEngine');
const VersionControlEngine = require('./src/core/VersionControlEngine');
const SmartInputProcessor = require('./src/core/SmartInputProcessor');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = './uploads';
    fs.ensureDirSync(uploadDir);
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}-${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.txt', '.json', '.csv', '.log', '.irp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Allowed: .txt, .json, .csv, .log, .irp'));
    }
  },
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// Initialize core components
const playbookGenerator = new PlaybookGenerator();
const fieldMappingEngine = new FieldMappingEngine();
const mitreMapper = new MITREMapper();
const reverseQueryEngine = new ReverseQueryEngine();
const approvalGateEngine = new ApprovalGateEngine();
const versionControlEngine = new VersionControlEngine();
const smartInputProcessor = new SmartInputProcessor();

// Load existing versions on startup
versionControlEngine.loadVersions().catch(console.error);

// Serve static files
app.use(express.static(path.join(__dirname, 'dist')));

// API Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Get MITRE ATT&CK techniques
app.get('/api/mitre/techniques', async (req, res) => {
  try {
    const techniques = await mitreMapper.getAllTechniques();
    res.json(techniques);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get field mappings for platforms
app.get('/api/field-mappings/:platform', (req, res) => {
  try {
    const { platform } = req.params;
    const mappings = fieldMappingEngine.getPlatformMappings(platform);
    res.json(mappings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Generate playbook from text input
app.post('/api/playbook/generate/text', async (req, res) => {
  try {
    const { text, platform, options } = req.body;
    
    if (!text || !platform) {
      return res.status(400).json({ error: 'Text and platform are required' });
    }

    // Use smart processing with LLM enhancement
    const processedInput = await smartInputProcessor.processInput(text, 'text', options);
    
    const result = await playbookGenerator.generateFromProcessedInput(processedInput, platform, options);
    
    res.json({
      ...result,
      smart_processing: {
        llm_enhanced: processedInput.llm_enhanced,
        llm_provider: processedInput.llm_provider,
        llm_confidence: processedInput.llm_confidence,
        llm_insights: processedInput.llm_insights
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Generate playbook from file upload
app.post('/api/playbook/generate/file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { platform, options } = req.body;
    const filePath = req.file.path;

    const result = await playbookGenerator.generateFromFile(filePath, platform, JSON.parse(options || '{}'));
    
    // Clean up uploaded file
    await fs.remove(filePath);
    
    res.json(result);
  } catch (error) {
    // Clean up uploaded file on error
    if (req.file) {
      await fs.remove(req.file.path);
    }
    res.status(500).json({ error: error.message });
  }
});

// Reverse query search
app.post('/api/playbook/reverse-search', async (req, res) => {
  try {
    const { query, platform, filters } = req.body;
    
    if (!query || !platform) {
      return res.status(400).json({ error: 'Query and platform are required' });
    }

    const results = await reverseQueryEngine.search(query, platform, filters);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get use case templates
app.get('/api/templates/use-cases', (req, res) => {
  try {
    const templates = playbookGenerator.getUseCaseTemplates();
    res.json(templates);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Validate playbook schema
app.post('/api/playbook/validate', (req, res) => {
  try {
    const { playbook } = req.body;
    const validation = playbookGenerator.validatePlaybook(playbook);
    res.json(validation);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Export playbook
app.post('/api/playbook/export', (req, res) => {
  try {
    const { playbook, format } = req.body;
    const exported = playbookGenerator.exportPlaybook(playbook, format);
    
    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename="playbook.json"');
      res.send(exported);
    } else {
      res.json(exported);
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Version Control API Routes

// Create version for playbook
app.post('/api/playbook/:playbookId/version', async (req, res) => {
  try {
    const { playbookId } = req.params;
    const { changeDescription, author, branch } = req.body;
    
    // Get current playbook (in a real implementation, this would come from database)
    const { playbook } = req.body;
    
    if (!playbook) {
      return res.status(400).json({ error: 'Playbook data is required' });
    }
    
    const version = await versionControlEngine.createVersion(
      playbook, 
      changeDescription || 'Auto-generated version',
      author || 'system',
      branch || 'main'
    );
    
    res.json({ success: true, version });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get version history for playbook
app.get('/api/playbook/:playbookId/versions', (req, res) => {
  try {
    const { playbookId } = req.params;
    const { branch } = req.query;
    
    const versions = versionControlEngine.getVersionHistory(playbookId, branch);
    res.json({ versions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get specific version
app.get('/api/playbook/:playbookId/version/:versionId', (req, res) => {
  try {
    const { versionId } = req.params;
    const version = versionControlEngine.getVersion(versionId);
    
    if (!version) {
      return res.status(404).json({ error: 'Version not found' });
    }
    
    res.json({ version });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get latest version
app.get('/api/playbook/:playbookId/latest', (req, res) => {
  try {
    const { playbookId } = req.params;
    const { branch } = req.query;
    
    const version = versionControlEngine.getLatestVersion(playbookId, branch || 'main');
    
    if (!version) {
      return res.status(404).json({ error: 'No versions found' });
    }
    
    res.json({ version });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Compare versions
app.get('/api/playbook/:playbookId/compare/:version1/:version2', (req, res) => {
  try {
    const { version1, version2 } = req.params;
    const comparison = versionControlEngine.compareVersions(version1, version2);
    res.json({ comparison });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create branch
app.post('/api/playbook/:playbookId/branch', async (req, res) => {
  try {
    const { playbookId } = req.params;
    const { branchName, fromVersionId, author } = req.body;
    
    if (!branchName || !fromVersionId) {
      return res.status(400).json({ error: 'Branch name and source version are required' });
    }
    
    const branch = await versionControlEngine.createBranch(
      playbookId,
      branchName,
      fromVersionId,
      author || 'system'
    );
    
    res.json({ success: true, branch });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Merge branch
app.post('/api/playbook/:playbookId/merge', async (req, res) => {
  try {
    const { playbookId } = req.params;
    const { sourceBranch, targetBranch, author } = req.body;
    
    if (!sourceBranch) {
      return res.status(400).json({ error: 'Source branch is required' });
    }
    
    const mergedVersion = await versionControlEngine.mergeBranch(
      playbookId,
      sourceBranch,
      targetBranch || 'main',
      author || 'system'
    );
    
    res.json({ success: true, mergedVersion });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create tag
app.post('/api/playbook/:playbookId/tag', async (req, res) => {
  try {
    const { playbookId } = req.params;
    const { tagName, versionId, description, author } = req.body;
    
    if (!tagName || !versionId) {
      return res.status(400).json({ error: 'Tag name and version ID are required' });
    }
    
    const tag = await versionControlEngine.createTag(
      playbookId,
      tagName,
      versionId,
      author || 'system',
      description || ''
    );
    
    res.json({ success: true, tag });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get tags for playbook
app.get('/api/playbook/:playbookId/tags', (req, res) => {
  try {
    const { playbookId } = req.params;
    const tags = versionControlEngine.getTags(playbookId);
    res.json({ tags });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Rollback to version
app.post('/api/playbook/:playbookId/rollback', async (req, res) => {
  try {
    const { playbookId } = req.params;
    const { versionId, author, reason } = req.body;
    
    if (!versionId) {
      return res.status(400).json({ error: 'Version ID is required' });
    }
    
    const rollbackVersion = await versionControlEngine.rollbackToVersion(
      playbookId,
      versionId,
      author || 'system',
      reason || ''
    );
    
    res.json({ success: true, rollbackVersion });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get audit trail
app.get('/api/playbook/:playbookId/audit', (req, res) => {
  try {
    const { playbookId } = req.params;
    const { action, limit } = req.query;
    
    const auditTrail = versionControlEngine.getAuditTrail(
      playbookId,
      action,
      limit ? parseInt(limit) : 100
    );
    
    res.json({ auditTrail });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get version statistics
app.get('/api/playbook/:playbookId/stats', (req, res) => {
  try {
    const { playbookId } = req.params;
    const stats = versionControlEngine.getVersionStats(playbookId);
    res.json({ stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Export version history
app.get('/api/playbook/:playbookId/export', async (req, res) => {
  try {
    const { playbookId } = req.params;
    const { format } = req.query;
    
    const exportData = await versionControlEngine.exportVersionHistory(
      playbookId,
      format || 'json'
    );
    
    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${playbookId}-history.json"`);
      res.send(exportData);
    } else {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${playbookId}-history.csv"`);
      res.send(exportData);
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Approval Gate API Routes

// Evaluate approval gates for playbook
app.post('/api/playbook/:playbookId/approval/evaluate', async (req, res) => {
  try {
    const { playbookId } = req.params;
    const { playbook, executionContext } = req.body;
    
    if (!playbook) {
      return res.status(400).json({ error: 'Playbook data is required' });
    }
    
    const approvalDecision = await approvalGateEngine.evaluateApprovalGates(
      playbook,
      executionContext || {}
    );
    
    res.json({ approvalDecision });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get approval request
app.get('/api/approval/:approvalId', (req, res) => {
  try {
    const { approvalId } = req.params;
    const request = approvalGateEngine.getApprovalRequest(approvalId);
    
    if (!request) {
      return res.status(404).json({ error: 'Approval request not found' });
    }
    
    res.json({ request });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Approve request
app.post('/api/approval/:approvalId/approve', async (req, res) => {
  try {
    const { approvalId } = req.params;
    const { approver, comments } = req.body;
    
    if (!approver) {
      return res.status(400).json({ error: 'Approver is required' });
    }
    
    const request = await approvalGateEngine.approveRequest(approvalId, approver, comments);
    res.json({ success: true, request });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reject request
app.post('/api/approval/:approvalId/reject', async (req, res) => {
  try {
    const { approvalId } = req.params;
    const { approver, reason } = req.body;
    
    if (!approver || !reason) {
      return res.status(400).json({ error: 'Approver and reason are required' });
    }
    
    const request = await approvalGateEngine.rejectRequest(approvalId, approver, reason);
    res.json({ success: true, request });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get pending approvals
app.get('/api/approvals/pending', (req, res) => {
  try {
    const { user } = req.query;
    const pending = approvalGateEngine.getPendingApprovals(user);
    res.json({ pending });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get approval history
app.get('/api/approval/:approvalId/history', (req, res) => {
  try {
    const { approvalId } = req.params;
    const history = approvalGateEngine.getApprovalHistory(approvalId);
    res.json({ history });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get approval statistics
app.get('/api/approvals/stats', (req, res) => {
  try {
    const stats = approvalGateEngine.getApprovalStats();
    res.json({ stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Serve the frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`SOAR Playbook Generator running on port ${PORT}`);
  console.log(`Access the application at: http://localhost:${PORT}`);
});

module.exports = app;
