# Test Suite

This directory contains tests to run against the MCP package. It currently consists of a single [e2e.js](./e2e.js) script to run with test keys.

## Prerequisites

- Node.js 18+ installed
- Google project setup as describe in the main [README](../README.md)
- (optional) Dotenv for env file management (optional)

## Running Jest E2E Tests

### Configuration via Env File

1. Configure the required environment variables:
```bash
export CLIENT_ID=
export CLIENT_SECRET=
export REFRESH_TOKEN=

2. Run the test suite:
```bash
pnpm i && pnpm build && pnpm test
```
