FROM node:22-alpine
WORKDIR /workspace/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend .
