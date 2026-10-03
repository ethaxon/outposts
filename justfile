# justfile - Command Runner
#
# Role: Discoverable task interface for the outposts workspace
# - Prerequisites: Toolchain managed by mise (run `just setup` first)
# - Organization: Domain recipes live in justfiles/ and are imported here
#   so `just <recipe>` retains a flat public CLI.
#
# Usage:
#   just <recipe> [args...]   - Run command
#   just --list               - List available commands

set dotenv-load := true

# PowerShell 7.4+ keeps the recipe text and later arguments as separate argv.
[windows]
set shell := ["pwsh.exe", "-NoLogo", "-CommandWithArgs"]

# $0 / $args[0] is the recipe name. Use this only when every parameter is variadic.
recipe_args := if os() == "windows" { "@($args | Select-Object -Skip 1)" } else { '"$@"' }

import 'justfiles/workspace.just'
import 'justfiles/dev.just'
import 'justfiles/build.just'
import 'justfiles/container.just'
