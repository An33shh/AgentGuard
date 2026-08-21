FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .

# Next.js inlines NEXT_PUBLIC_* vars into the client bundle at build time —
# setting it only at container runtime (as a docker-compose `environment:`)
# has no effect on already-built client JS, so it must be a build ARG here.
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
RUN npm run build

FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

EXPOSE 3747

ENV PORT=3747
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]
