#!/usr/bin/env bash
set -euo pipefail

# Keep task merges reproducible: install any newly declared packages, then
# validate the curriculum as part of the production build.
npm install --no-audit --no-fund
npm run build