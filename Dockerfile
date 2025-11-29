# Dockerfile for MXBikes Stats Server on Fly.io
FROM node:20-slim

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --omit=dev

# Copy source code
COPY . .

# Expose port
EXPOSE 8080

# Start the server
CMD ["node", "server.js"]
