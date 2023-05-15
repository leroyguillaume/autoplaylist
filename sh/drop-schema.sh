#!/bin/bash

docker compose exec postgres psql -U autoplaylist -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
