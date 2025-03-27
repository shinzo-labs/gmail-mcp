FROM node:lts-alpine

WORKDIR /app

ENV NODE_OPTIONS="--max-old-space-size=4096"
ENV HOME="/home/node"

RUN npm install -g pnpm

COPY --chown=node:node ["./package.json", "./pnpm-lock.yaml", "./"]

RUN pnpm fetch
RUN pnpm install -r --offline

COPY --chown=node:node ["./src", "./tsconfig.json", "./"]

RUN pnpm run build

USER node

# Create logging directory with proper ownership
RUN mkdir -p /home/node/.gmail-mcp
RUN chown -R node:node /home/node/.gmail-mcp
RUN chmod -R 755 /home/node/.gmail-mcp

ENTRYPOINT ["pnpm", "run", "start"]
