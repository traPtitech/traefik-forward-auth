# Start by building the application.
FROM --platform=$BUILDPLATFORM golang:1.22 as build

WORKDIR /usr/src/traefik-forward-auth
ENV CGO_ENABLED 0

COPY ./go.* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -o ./traefik-forward-auth -ldflags "-s -w" -tags "viper_bind_struct" ./cmd

# Now copy it into our base image.
FROM gcr.io/distroless/static-debian11:nonroot

COPY --from=build /usr/src/traefik-forward-auth/traefik-forward-auth /usr/bin/traefik-forward-auth

ENTRYPOINT ["/usr/bin/traefik-forward-auth"]
CMD []

LABEL org.opencontainers.image.title=traefik-forward-auth
LABEL org.opencontainers.image.description="Forward authentication service for the Traefik reverse proxy"
LABEL org.opencontainers.image.licenses=MIT
