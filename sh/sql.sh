#!/bin/bash

docker compose exec postgres psql -U autoplaylist -c "$2"
