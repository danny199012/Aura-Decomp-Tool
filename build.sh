#!/bin/bash
set -e
echo '== frontend =='
npm install && npm run build
echo '== tauri =='
npm run tauri build
echo '== aura-cli =='
(cd cli && cargo build --release)
echo 'done: GUI->src-tauri/target/release/bundle/, CLI->cli/target/release/aura-cli'
