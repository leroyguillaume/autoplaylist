#!/bin/sh

set -e

url=postgres://autoplaylist:autoplaylist@localhost:5432/autoplaylist

sqlx database drop -D $url
sqlx database create -D $url
sqlx migrate run -D $url --source common/resources/main/db/pg/migrations
cargo sqlx prepare -D $url --workspace
