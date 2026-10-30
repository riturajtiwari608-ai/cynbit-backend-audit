# Multi-stage lightweight Node.js Dockerfile
FROM node:20-alpine AS base

WORKDIR /app

# Copy dependency manifests
COPY package.json ./

# Copy source code
COPY src ./src
COPY public ./public
COPY tests ./tests

# Environment variables
ENV NODE_ENV=production
ENV PORT=3000

# Expose server port
EXPOSE 3000

# Run automated tests before container start
RUN node --test tests/*.test.js

# Start production server
CMD ["node", "src/index.js"]
