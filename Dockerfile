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

# runtime

FROM alpine AS rust-runtime

RUN <<EOF
adduser -D app
apk add --no-cache bind-tools
EOF

USER app

# api

FROM rust-runtime AS api

COPY --chown=app:app --from=rust-build /opt/autoplaylist/target/release/autoplaylist-api /usr/local/bin/autoplaylist-api

ENTRYPOINT [ "/usr/local/bin/autoplaylist-api" ]

EXPOSE 8000

# cli

FROM rust-runtime AS cli

COPY --chown=app:app --from=rust-build /opt/autoplaylist/target/release/autoplaylist /usr/local/bin/autoplaylist

ENTRYPOINT [ "/usr/local/bin/autoplaylist" ]

# sync

FROM rust-runtime AS sync

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
