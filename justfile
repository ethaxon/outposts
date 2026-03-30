set windows-shell := ["pwsh.exe", "-c"]
set dotenv-load := true

setup:
  pnpm install
  pnpm exec prek install
  cargo check --workspace --all-features

dev-confluence:
  watchexec -r -e rs,toml,yaml,yml,env,json -- cargo run -p confluence --bin confluence_server

dev-webui:
  pnpm exec nx serve outposts-web

dev-proxy:
  npm run start -w dev-proxy

build-webui:
  pnpm exec nx build outposts-web

build-confluence:
  cargo build --release -p confluence --bin confluence_server

lint:
  pnpm lint

lint-fix:
  pnpm lint:fix

format:
  pnpm format

format-check:
  pnpm format:check

fix:
  just lint-fix
  just format

container-build:
  docker compose build

container-deploy:
  docker compose up -d

dev-deps:
  docker compose -f docker-compose.dev-deps.yml up -d --remove-orphans

dev-deps-down:
  docker compose -f docker-compose.dev-deps.yml down
