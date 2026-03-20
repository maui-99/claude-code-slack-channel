FROM oven/bun:1-slim

WORKDIR /app

COPY package.json bun.lockb* ./
RUN bun install --frozen-lockfile 2>/dev/null || bun install

COPY server.ts ./

# State dir is mounted at runtime: -v ~/.claude/channels/slack:/state
ENV SLACK_STATE_DIR=/state

ENTRYPOINT ["bun", "server.ts"]
