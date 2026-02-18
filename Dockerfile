# Use Node.js LTS image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Clean npm cache and install dependencies
RUN npm cache clean --force && \
    npm install --no-audit --no-fund

# Copy package files
COPY package*.json ./

# Copy source code
COPY . .

# Create data directory for versions
RUN mkdir -p src/data

# Build frontend
RUN npm run build:client

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/health', (res) => { res.statusCode === 200 ? process.exit(0) : process.exit(1) })"

# Start the application
CMD ["npm", "start"]
