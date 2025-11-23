FROM mcr.microsoft.com/playwright:v1.56.1-jammy

WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000

COPY package*.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY public ./public

# Persist browser profiles/cookies outside the image
VOLUME ["/app/.twdrops-profile"]

EXPOSE 3000

CMD ["npm", "start"]
