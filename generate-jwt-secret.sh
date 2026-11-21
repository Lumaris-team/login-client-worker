#!/bin/bash
# Generate random JWT secret and update wrangler.jsonc before deployment

JWT_SECRET=$(openssl rand -base64 32)

# Update wrangler.jsonc with the random JWT secret
sed -i '' "s/__GENERATE_RANDOM_AT_DEPLOY__/$JWT_SECRET/g" wrangler.jsonc

echo "JWT_SECRET_KEY generated and updated in wrangler.jsonc"
