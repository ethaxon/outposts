# Start full local development layout in zellij (Unix only)
[unix]
[group('dev')]
[positional-arguments]
dev *args:
    zellij --layout zellij-dev.kdl {{recipe_args}}

# Run confluence backend with file watching
[group('dev')]
[positional-arguments]
dev-confluence *args:
    watchexec -r -e rs,toml,yaml,yml,env,json -- cargo run -p confluence --bin confluence_server -- {{recipe_args}}

# Start outposts-web development server
[group('dev')]
[positional-arguments]
dev-webui *args:
    pnpm exec nx serve outposts-web {{recipe_args}}

# Start local development proxy
[group('dev')]
[positional-arguments]
dev-proxy *args:
    pnpm --filter dev-proxy run start {{recipe_args}}

# Start local development dependency containers
[group('dev')]
[positional-arguments]
dev-deps *args:
    docker compose -f docker-compose.dev-deps.yml up -d --remove-orphans {{recipe_args}}

# Stop local development dependency containers
[group('dev')]
[positional-arguments]
dev-deps-down *args:
    docker compose -f docker-compose.dev-deps.yml down {{recipe_args}}
