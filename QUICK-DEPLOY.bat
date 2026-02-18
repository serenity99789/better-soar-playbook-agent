@echo off
echo ========================================
echo SOAR Playbook Generator - Quick Deploy
echo ========================================
echo.

echo This script will help you deploy to Railway + GitHub
echo.

echo Step 1: Initialize Git Repository
git init
git add .
git commit -m "Initial commit: SOAR Playbook Generator Platform"

echo.
echo Step 2: Create GitHub Repository
echo.
echo Please go to https://github.com/new and create a new repository named:
echo "soar-playbook-generator"
echo.
echo Then copy the repository URL and paste it below:
set /p repo_url="Repository URL: "

git remote add origin %repo_url%
git branch -M main
git push -u origin main

echo.
echo Step 3: Open Railway for Deployment
echo.
echo Opening Railway deployment page...
start https://railway.app/new

echo.
echo Instructions:
echo 1. Click "Deploy from GitHub repo"
echo 2. Connect your GitHub account
echo 3. Select "soar-playbook-generator"
echo 4. Click "Deploy Now"
echo.
echo Your app will be live at: https://your-app-name.up.railway.app
echo.
pause
