# Test Suite

This directory contains tests to run against the MCP package. It currently consists of a single [e2e.test.ts](./e2e.test.ts) script to run with test keys.

## Prerequisites

Be sure to follow the prerequisite installation steps from [CONTRIBUTING.md](../CONTRIBUTING.md) before trying to run the test suite. The suite will perform a few operations including creating, updating, and deleting draft emails, but the there should be no change to the account "state" at the end if all tests execute correctly.

## Running Jest E2E Tests

1. Configure the required environment variables:
```bash
export CLIENT_ID=
export CLIENT_SECRET=
export REFRESH_TOKEN=
export PORT= #For Streamable HTTP transport if 3000 is unavailable
```

2. Run the test suite:
```bash
pnpm i && pnpm build && pnpm test
```
