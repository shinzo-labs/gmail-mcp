FROM node:lts-alpine

WORKDIR /app

ENV NODE_OPTIONS="--max-old-space-size=4096"

RUN npm install -g pnpm

COPY --chown=node:node ["./package.json", "./pnpm-lock.yaml", "./"]

RUN pnpm fetch
RUN pnpm install -r --offline

COPY --chown=node:node ["./src", "./tsconfig.json", "./"]

RUN pnpm run build

USER node

# Create logging directory
RUN mkdir -p /home/node/.gmail-mcp
RUN chmod 755 /home/node/.gmail-mcp

ENTRYPOINT ["pnpm", "run", "start"]
