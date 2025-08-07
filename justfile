set windows-shell := ["pwsh.exe", "-c"]

dev-confluence:
  watchexec -r -e rs,toml,yaml,yml,env,json -- cargo run -p confluence --bin confluence_server

dev-webui:
  pnpm exec nx serve outposts-web

dev-proxy:
  npm run start -w dev-proxy

container-build:
  docker compose build

container-deploy:
  docker compose up -d

dev-deps:
  docker compose -f docker-compose.dev-deps.yml up -d
