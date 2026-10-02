# The reference webhook receiver of the e2e tests (test/e2e/compose.yml)
# and the lab. Built from the repository root, with the ignore file
# beside this Dockerfile (the root .dockerignore leaves test/ out).
FROM golang:1.27 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w" -o /out/subscriber ./test/e2e/subscriber

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/subscriber /usr/local/bin/subscriber
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["subscriber"]
