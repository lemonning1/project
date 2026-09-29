# syntax=docker/dockerfile:1

# 编译阶段只负责产出静态二进制。运行阶段不再带 Go 工具链和 shell。
FROM golang:1.26-alpine AS build

WORKDIR /src

RUN addgroup -g 65532 -S app \
    && adduser -u 65532 -S -G app app

COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0 \
    GOFLAGS=-buildvcs=false

RUN go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server \
    && go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client \
    && chmod 755 /out/server /out/client

FROM scratch AS server

COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /out/server /server
COPY rules/fingerprints.json /rules/fingerprints.json

USER 65532:65532
EXPOSE 8080
ENV LISTEN_ADDR=:8080 \
    RULES_PATH=/rules/fingerprints.json
ENTRYPOINT ["/server"]
HEALTHCHECK --interval=5s --timeout=2s --start-period=2s --retries=12 \
    CMD ["/server", "healthcheck"]

FROM scratch AS client

COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /out/client /client
COPY testdata/input.json /data/input.json

USER 65532:65532
ENV FINGERPRINT_SERVER=http://server:8080 \
    FINGERPRINT_INPUT=/data/input.json
ENTRYPOINT ["/client"]
