# Small, fast Node image
FROM node:20-alpine

WORKDIR /app

# Install deps
COPY package*.json ./
RUN npm ci --omit=dev

# Copy app code
COPY . .

ENV NODE_ENV=production
EXPOSE 8080

# Cloud Run injects PORT; your server reads process.env.PORT already
CMD ["node", "server.js"]
