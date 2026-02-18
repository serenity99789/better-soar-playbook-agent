// Simple test server to verify setup
const http = require('http');

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>SOAR Playbook Generator - Test</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .status { padding: 20px; background: #e8f5e8; border-radius: 5px; }
            .error { padding: 20px; background: #ffe8e8; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ SOAR Playbook Generator</h1>
            <div class="status">
                <h2>✅ Server is Running!</h2>
                <p>The test server is working correctly.</p>
                <p><strong>Next Steps:</strong></p>
                <ol>
                    <li>Install Node.js from <a href="https://nodejs.org/">https://nodejs.org/</a></li>
                    <li>Open Command Prompt as Administrator</li>
                    <li>Navigate to: <code>cd c:\\Users\\Srini\\CascadeProjects\\better-soar-playbook-agent</code></li>
                    <li>Run: <code>npm install</code></li>
                    <li>Run: <code>npm start</code></li>
                </ol>
            </div>
            <h3>Project Files Created:</h3>
            <ul>
                <li>✅ Core Engines (8 modules)</li>
                <li>✅ Web Interface</li>
                <li>✅ API Server</li>
                <li>✅ Configuration Files</li>
                <li>✅ Sample Data</li>
                <li>✅ Documentation</li>
            </ul>
        </div>
    </body>
    </html>
  `);
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Test server running at http://localhost:${PORT}`);
  console.log('Open your browser and navigate to http://localhost:3000');
});
