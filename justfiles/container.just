# Build container images with Docker Compose
[group('container')]
[positional-arguments]
container-build *args:
    docker compose build {{recipe_args}}

# Deploy container stack with Docker Compose
[group('container')]
[positional-arguments]
container-deploy *args:
    docker compose up -d {{recipe_args}}
