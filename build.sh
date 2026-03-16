#!/bin/bash
set -e

mkdir -p dist

# Build JS bundle
npx esbuild src/main.ts --bundle --minify --outfile=dist/app.js --target=es2022

# Create single-file version with inlined JS
node -e "
const fs = require('fs');
const html = fs.readFileSync('index.html', 'utf8');
const js = fs.readFileSync('dist/app.js', 'utf8');
const out = html.replace('<script src=\"dist/app.js\"></script>', '<script>' + js + '</script>');
fs.writeFileSync('dist/index.html', out);
"

echo "Build complete:"
echo "  dist/app.js     $(wc -c < dist/app.js | tr -d ' ') bytes"
echo "  dist/index.html $(wc -c < dist/index.html | tr -d ' ') bytes"
