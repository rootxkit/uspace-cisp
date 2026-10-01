# The uspace-cisp Go image: api, deliver and cispctl in one image, the
# process chosen by the compose `command` (["api"], ["deliver"],
# ["cispctl", "migrate"]). Built in CI only, never on the server.

FROM golang:1.27 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
# No `go mod download`: it would fetch the tool directives' modules
# (sqlc, goose) too. The build fetches only what the binaries import.
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    for cmd in api deliver cispctl; do \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "/out/${cmd}" "./cmd/${cmd}" || exit 1; \
    done

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/api /out/deliver /out/cispctl /usr/local/bin/
USER nonroot:nonroot
EXPOSE 8080 8081
CMD ["api"]
