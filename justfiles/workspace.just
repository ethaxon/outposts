# Install toolchain and workspace dependencies, then verify Rust workspace
[default]
[group('workspace')]
setup:
    mise install
    pnpm install
    cargo check --workspace --all-features

# Run workspace linter
[group('quality')]
[positional-arguments]
lint *args:
    pnpm lint {{recipe_args}}

# Auto-fix workspace lint issues
[group('quality')]
[positional-arguments]
lint-fix *args:
    pnpm lint:fix {{recipe_args}}

# Format workspace files
[group('quality')]
[positional-arguments]
format *args:
    pnpm format {{recipe_args}}

# Check workspace formatting
[group('quality')]
[positional-arguments]
format-check *args:
    pnpm format:check {{recipe_args}}

# Auto-fix lint issues and format workspace files
[group('quality')]
fix: lint-fix format
