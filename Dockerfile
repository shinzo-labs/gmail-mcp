FROM node:lts-alpine

WORKDIR /app

ENV NODE_OPTIONS="--max-old-space-size=4096"
ENV MCP_CONFIG_DIR=/home/node/.gmail-mcp

# Create logging directory with proper ownership
RUN mkdir -p /home/node/.gmail-mcp && \
    chown -R node:node /home/node/.gmail-mcp && \
    chmod -R 755 /home/node/.gmail-mcp

RUN npm install -g pnpm

COPY --chown=node:node package.json pnpm-lock.yaml ./

RUN pnpm fetch
RUN pnpm install -r --offline

COPY --chown=node:node src/ ./src/
COPY --chown=node:node tsconfig.json ./

RUN pnpm build

USER node

ENTRYPOINT ["pnpm", "run", "start"]
