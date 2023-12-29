# rust-build

FROM rust:alpine AS rust-build

RUN apk add --no-cache libressl-dev musl-dev

WORKDIR /opt/autoplaylist

COPY .sqlx .sqlx
COPY api api
COPY cli cli
COPY common common
COPY sync sync
COPY Cargo.* .

RUN cargo build --release

# api

FROM alpine AS api

ENV SERVER_ADDR 0.0.0.0:8000

RUN <<EOF
apk add --no-cache curl
adduser -D app
EOF

USER app

COPY --chown=app:app --from=rust-build /opt/autoplaylist/target/release/autoplaylist-api /usr/local/bin/autoplaylist-api

ENTRYPOINT [ "/usr/local/bin/autoplaylist-api" ]

EXPOSE 8000

# cli

FROM alpine AS cli

RUN adduser -D app

USER app

COPY --chown=app:app --from=rust-build /opt/autoplaylist/target/release/autoplaylist /usr/local/bin/autoplaylist

ENTRYPOINT [ "/usr/local/bin/autoplaylist" ]

# sync

FROM alpine AS sync

RUN adduser -D app

USER app

COPY --chown=app:app --from=rust-build /opt/autoplaylist/target/release/autoplaylist-sync /usr/local/bin/autoplaylist-sync

ENTRYPOINT [ "/usr/local/bin/autoplaylist-sync" ]

# node-build

FROM node AS node-build

WORKDIR /opt/autoplaylist

COPY webapp .

RUN <<EOF
npm ci
npm run build
EOF

# webapp

FROM nginx:alpine AS webapp

COPY docker/webapp/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/webapp/00-config.sh /docker-entrypoint.d/10-config.sh

RUN <<EOF
apk add --no-cache curl
chmod +x /docker-entrypoint.d/10-config.sh
EOF

COPY --from=node-build /opt/autoplaylist/build /usr/share/nginx/html

EXPOSE 80
