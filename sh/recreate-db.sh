#!/bin/sh

sqlx database drop -D postgres://autoplaylist:autoplaylist@localhost:5432/autoplaylist
sqlx database create -D postgres://autoplaylist:autoplaylist@localhost:5432/autoplaylist
sqlx migrate run \
    -D postgres://autoplaylist:autoplaylist@localhost:5432/autoplaylist \
    --source common/resources/main/db/pg/migrations
