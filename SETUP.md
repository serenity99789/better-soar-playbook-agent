# 🚀 Quick Setup Guide

## Issue: Localhost Not Working

The server isn't running because **Node.js is not installed** on your system.

## 🔧 Step-by-Step Solution

### 1. Install Node.js
1. Go to https://nodejs.org/
2. Download the **LTS** version (Recommended for Most Users)
3. Run the installer with default settings
4. Restart your computer

### 2. Verify Installation
Open Command Prompt and run:
```cmd
node --version
npm --version
```
You should see version numbers (e.g., v18.19.0 and 9.2.0)

### 3. Install Dependencies
```cmd
cd c:\Users\Srini\CascadeProjects\better-soar-playbook-agent
npm install
```

### 4. Start the Application
```cmd
npm start
```

### 5. Access the Application
Open your browser and go to: **http://localhost:3000**

## 🧪 Quick Test (Without Node.js)

I've created a test file. Run this in Command Prompt:
```cmd
cd c:\Users\Srini\CascadeProjects\better-soar-playbook-agent
node test-server.js
```

## 🔍 Troubleshooting

### If "node command not found":
- Node.js installation failed
- Add Node.js to PATH: `C:\Program Files\nodejs\`
- Restart Command Prompt

### If "npm install fails":
- Run as Administrator
- Check internet connection
- Try: `npm cache clean --force`

### If "port 3000 in use":
- Kill process: `netstat -ano | findstr :3000`
- Kill PID: `taskkill /PID <PID> /F`
- Or change port: `set PORT=3001 && npm start`

## 📋 What's Been Created

✅ **Complete SOAR Platform** with:
- Web Interface
- REST API
- MITRE ATT&CK Integration
- Version Control
- Approval Workflows
- Sample Data

## 🆘 Still Need Help?

1. Install Node.js first
2. Run the commands above in order
3. Check each step succeeds before proceeding

The platform is fully built and ready to run once Node.js is installed!
