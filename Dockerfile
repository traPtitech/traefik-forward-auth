# Start by building the application.
FROM --platform=$BUILDPLATFORM golang:1.25@sha256:dd7d32e19b28621cd982082397fc0510d396805b717d5e77466aa2dd692340de AS build

WORKDIR /usr/src/traefik-forward-auth
ENV CGO_ENABLED=0

COPY ./go.* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -o ./traefik-forward-auth -ldflags "-s -w" ./cmd

# Now copy it into our base image.
FROM gcr.io/distroless/static-debian11:nonroot@sha256:63ebe035fbdd056ed682e6a87b286d07d3f05f12cb46f26b2b44fc10fc4a59ed

COPY --from=build /usr/src/traefik-forward-auth/traefik-forward-auth /usr/bin/traefik-forward-auth

ENTRYPOINT ["/usr/bin/traefik-forward-auth"]
CMD []

LABEL org.opencontainers.image.title=traefik-forward-auth
LABEL org.opencontainers.image.description="Forward authentication service for the Traefik reverse proxy"
LABEL org.opencontainers.image.licenses=MIT
