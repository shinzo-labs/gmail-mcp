import path from 'path'
import os from 'os'

export const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp')
export const LOG_PATH = process.env.LOG_PATH || path.join(CONFIG_DIR, 'gmail-mcp.log')
export const GMAIL_OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json')
export const GMAIL_CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json')
