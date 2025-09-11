FROM node:18-alpine
WORKDIR /app

# Install tini for proper signal handling
RUN apk add --no-cache tini curl

COPY package*.json ./
RUN npm ci || npm install

COPY . .

ENV PORT=5000
EXPOSE 5000

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["npm", "start"]


