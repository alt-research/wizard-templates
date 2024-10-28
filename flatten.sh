#!/bin/bash

# Define the templates directory
TEMPLATES_DIR="src/templates"
FLATTENED_DIR="flattened"

# Create the flattened directory if it doesn't exist
mkdir -p "$FLATTENED_DIR"

# Find all files ending with 'Template.sol' in the templates directory
FILES=$(find "$TEMPLATES_DIR" -type f -name '*Template.sol')

# Loop through each file and run the flatten command
for FILE in $FILES; do
    BASENAME=$(basename "$FILE" .sol)
    OUTPUT_FILE="${FLATTENED_DIR}/${BASENAME}.flattened.sol"
    forge flatten --output "$OUTPUT_FILE" "$FILE"
done
