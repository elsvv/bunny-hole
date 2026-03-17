#!/bin/bash
set -e

rm -rf dist && mkdir -p dist

# Build with code splitting — QR loaded lazily
npx esbuild src/main.ts --bundle --minify --splitting --format=esm --outdir=dist --target=es2022

# Copy HTML with module script tag
cp index.html dist/index.html

echo "Build complete:"
for f in dist/*.js; do
  echo "  $(basename $f)  $(wc -c < "$f" | tr -d ' ') bytes"
done
echo "  index.html  $(wc -c < dist/index.html | tr -d ' ') bytes"
echo "  total JS:   $(cat dist/*.js | wc -c | tr -d ' ') bytes"
echo "  gzipped:    $(cat dist/*.js | gzip -c | wc -c | tr -d ' ') bytes"
