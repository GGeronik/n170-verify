FROM node:22-bookworm-slim AS deps

WORKDIR /srv/n170-verify-web
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

FROM node:22-bookworm-slim AS builder

WORKDIR /srv/n170-verify-web
COPY --from=deps /srv/n170-verify-web/node_modules ./node_modules
COPY . .

ARG NEXT_PUBLIC_N170_VERIFY_API_URL=http://127.0.0.1:8080
ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_N170_VERIFY_API_URL=${NEXT_PUBLIC_N170_VERIFY_API_URL}

RUN npm run build

FROM node:22-bookworm-slim AS runner

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

RUN groupadd --system --gid 10001 n170verify \
    && useradd --system --uid 10001 --gid n170verify --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin n170verify

WORKDIR /srv/n170-verify-web

COPY --from=builder --chown=n170verify:n170verify /srv/n170-verify-web/package.json ./package.json
COPY --from=builder --chown=n170verify:n170verify /srv/n170-verify-web/next.config.ts ./next.config.ts
COPY --from=builder --chown=n170verify:n170verify /srv/n170-verify-web/public ./public
COPY --from=builder --chown=n170verify:n170verify /srv/n170-verify-web/.next ./.next
COPY --from=builder --chown=n170verify:n170verify /srv/n170-verify-web/node_modules ./node_modules

USER n170verify:n170verify

EXPOSE 3000

CMD ["npm", "run", "start", "--", "--hostname", "0.0.0.0", "--port", "3000"]
