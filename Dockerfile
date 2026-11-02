FROM node:22-alpine
WORKDIR /app
COPY package.json server.mjs ./
COPY public ./public
ENV NODE_ENV=production DB_PATH=/data/vgn.db
EXPOSE 3000
CMD ["node", "server.mjs"]
