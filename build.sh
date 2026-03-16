#!/bin/bash
set -e
npx esbuild src/main.ts --bundle --minify --outfile=dist/app.js --target=es2022
echo "Build complete: dist/app.js ($(wc -c < dist/app.js) bytes)"
