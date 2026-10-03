# Build outposts-web frontend bundle
[group('build')]
[positional-arguments]
build-webui *args:
    pnpm exec nx build outposts-web {{recipe_args}}

# Build confluence backend release binary
[group('build')]
[positional-arguments]
build-confluence *args:
    cargo build --release -p confluence --bin confluence_server {{recipe_args}}
