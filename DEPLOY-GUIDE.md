# 🚀 Deploy to Railway + GitHub

## 🌟 Quick Deploy (5 Minutes)

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "Initial SOAR Playbook Generator"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/soar-playbook-generator.git
git push -u origin main
```

### Step 2: Deploy to Railway
1. Go to [railway.app](https://railway.app)
2. Click **"Deploy from GitHub repo"**
3. Connect your GitHub account
4. Select the `soar-playbook-generator` repository
5. Click **"Deploy Now"**

### Step 3: Configure Environment
Railway will automatically:
- Detect Node.js application
- Install dependencies
- Build frontend
- Start server on port 3000
- Provide you with a live URL

## 🔧 Alternative: Railway CLI

### Install Railway CLI
```bash
npm install -g @railway/cli
```

### Login and Deploy
```bash
railway login
railway init
railway up
```

## 🐳 Docker Support

The project includes:
- `Dockerfile` - Container configuration
- `railway.json` - Railway-specific settings
- `.dockerignore` - Exclude unnecessary files

## 🌐 Access Your App

After deployment, Railway will provide:
- **Live URL**: `https://your-app-name.up.railway.app`
- **Custom Domain**: Add your own domain
- **Environment Variables**: Configure settings
- **Logs**: Monitor application performance

## 📋 What Gets Deployed

✅ **Complete SOAR Platform**:
- Web interface with drag-and-drop
- REST API for all operations
- MITRE ATT&CK integration
- Version control system
- Approval workflows
- Sample data and templates

## 🔍 Features Available Online

- 📝 Generate playbooks from text/files
- 🔍 Reverse query search
- 🛡️ MITRE technique mapping
- ⚡ Risk-based approvals
- 📊 Version history
- 📥 Export capabilities

## 🛠️ Troubleshooting

### Build Fails
- Check `package.json` scripts
- Verify all files are committed
- Check Railway logs

### Port Issues
- Railway automatically handles port mapping
- No need to configure ports manually

### Environment Variables
Add in Railway dashboard:
- `NODE_ENV=production`
- `PORT=3000`

## 🔄 Auto-Deploy

Enable GitHub integration in Railway for automatic deployments when you push changes.

## 📊 Monitoring

Railway provides:
- Real-time logs
- Performance metrics
- Error tracking
- Uptime monitoring

## 🆘 Support

- Railway documentation: docs.railway.app
- GitHub issues for project-specific problems

---

**🎉 Your SOAR Playbook Generator will be live on the internet in minutes!**
