#!/bin/bash

docker compose exec db psql -U autoplaylist -c "$2"
