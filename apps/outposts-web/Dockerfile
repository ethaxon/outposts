FROM node:22-slim AS builder
RUN npm install -g pnpm@10.26.2
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
WORKDIR /usr/src/app
COPY . .
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store pnpm install --frozen-lockfile
RUN --mount=type=cache,id=angular,target=/usr/src/app/.angular \
  npm run build:outposts-web

FROM nginx:alpine
COPY ./apps/outposts-web/nginx.conf /etc/nginx/nginx.conf
COPY --from=builder /usr/src/app/dist/apps/outposts-web /usr/share/nginx/html
EXPOSE 80
