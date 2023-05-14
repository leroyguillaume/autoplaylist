#!/bin/bash

docker compose exec db psql -U autoplaylist -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
