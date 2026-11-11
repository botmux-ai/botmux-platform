FROM node:22-alpine AS web
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY vite.config.ts install.sh ./
COPY frontend frontend
COPY scripts scripts
RUN npx tsc -p frontend/tsconfig.json --noEmit && npx vite build && sh scripts/build-installer.sh

FROM golang:1.22-alpine AS server
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/botmux-platform ./cmd/botmux-platform

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -H botmux
COPY --from=server /out/botmux-platform /usr/local/bin/botmux-platform
COPY --from=web /src/dist/web /app/web
COPY --from=web /src/dist/install.sh /app/install.sh
ENV WEB_DIR=/app/web BOTMUX_INSTALLER_FILE=/app/install.sh
USER botmux
EXPOSE 8080
ENTRYPOINT ["botmux-platform"]
