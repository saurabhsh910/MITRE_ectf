#!/bin/bash

TEMPLATE_FILE="src/secrets_template.c"
OUTPUT_FILE="src/secrets.c"

touch $OUTPUT_FILE

KEY=`cat secrets/key.txt`
sed -e "s/KEY_PLACEHOLDER_SENTINEL_123456/$KEY/" $TEMPLATE_FILE > $OUTPUT_FILE

SEED=`cat secrets/randomseed.txt`
sed -e "s/RANDOM_SEED_PLACEHOLDER_SENTINEL_123456/$SEED/" -i $OUTPUT_FILE

