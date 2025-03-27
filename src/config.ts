import path from 'path'
import os from 'os'

export const MCP_CONFIG_DIR = process.env.MCP_CONFIG_DIR || path.join(os.homedir(), '.gmail-mcp')
export const LOG_PATH = path.join(MCP_CONFIG_DIR, 'gmail-mcp.log')
export const GMAIL_OAUTH_PATH = path.join(MCP_CONFIG_DIR, 'gcp-oauth.keys.json')
export const GMAIL_CREDENTIALS_PATH = path.join(MCP_CONFIG_DIR, 'credentials.json')
export const AUTH_SERVER_PORT = process.env.AUTH_SERVER_PORT || 3000
