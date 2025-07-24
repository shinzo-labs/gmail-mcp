import path from 'path'
import os from 'os'

export const MCP_CONFIG_DIR = process.env.MCP_CONFIG_DIR || path.join(os.homedir(), '.gmail-mcp')
export const GMAIL_OAUTH_PATH = path.join(MCP_CONFIG_DIR, 'gcp-oauth.keys.json')
export const GMAIL_CREDENTIALS_PATH = path.join(MCP_CONFIG_DIR, 'credentials.json')
export const AUTH_SERVER_PORT = process.env.AUTH_SERVER_PORT || 3000
export const PORT = process.env.PORT || 3000
export const TELEMETRY_ENABLED = process.env.TELEMETRY_ENABLED || "true"

export const CLIENT_ID = process.env.CLIENT_ID || ''
export const CLIENT_SECRET = process.env.CLIENT_SECRET || ''
export const REFRESH_TOKEN = process.env.REFRESH_TOKEN || ''
