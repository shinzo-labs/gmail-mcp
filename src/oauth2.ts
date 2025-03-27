import { AUTH_SERVER_PORT, CLIENT_ID, CLIENT_SECRET, GMAIL_CREDENTIALS_PATH, GMAIL_OAUTH_PATH, REFRESH_TOKEN } from "./config.js"
import { logger } from "./logger.js"
import { OAuth2Client } from "google-auth-library"
import fs from "fs"
import http from "http"
import open from "open"

const AUTH_SCOPES = [
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/gmail.compose',
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/gmail.settings.basic',
  'https://www.googleapis.com/auth/gmail.settings.sharing'
]

export const createOAuth2Client = () => {
  try {
    logger('info', 'Starting OAuth2Client creation')

    const oauthFilePresent = fs.existsSync(GMAIL_OAUTH_PATH)
    const credentialsFoundInEnv = (CLIENT_ID && CLIENT_SECRET && REFRESH_TOKEN)

    if (!credentialsFoundInEnv && !oauthFilePresent) {
      logger('error', 'Missing required environment variables or credentials file, see README for details.')
      process.exit(1)
    }

    let clientId: string
    let clientSecret: string

    if (oauthFilePresent) {
      const keysContent = fs.readFileSync(GMAIL_OAUTH_PATH, 'utf8')
      const parsedKeys = JSON.parse(keysContent)

      if (!parsedKeys?.installed.client_id || !parsedKeys.installed.client_secret) {
        logger('error', 'Invalid OAuth keys format', parsedKeys)
        process.exit(1)
      }

      clientId = parsedKeys.installed.client_id
      clientSecret = parsedKeys.installed.client_secret
    } else {
      clientId = CLIENT_ID
      clientSecret = CLIENT_SECRET
    }

    logger('info', 'Creating OAuth2Client with credentials')

    const oauth2Client = new OAuth2Client({
      clientId,
      clientSecret,
      redirectUri: `http://localhost:${AUTH_SERVER_PORT}/oauth2callback`
    })

    if (REFRESH_TOKEN) oauth2Client.setCredentials({ refresh_token: REFRESH_TOKEN })

    if (fs.existsSync(GMAIL_CREDENTIALS_PATH)) {
      logger('info', `Found existing credentials file at ${GMAIL_CREDENTIALS_PATH}`)
      const credentials = JSON.parse(fs.readFileSync(GMAIL_CREDENTIALS_PATH, 'utf8'))
      oauth2Client.setCredentials(credentials)
      logger('info', 'Successfully loaded existing credentials')
    } else {
      logger('info', `No existing credentials file found at ${GMAIL_CREDENTIALS_PATH}`)
    }

    return oauth2Client
  } catch (error: any) {
    logger('error', 'Failed to create OAuth2Client', { error: error.message })
    process.exit(1)
  }
}

export const launchAuthServer = async (oauth2Client: OAuth2Client) => new Promise((resolve, reject) => {
  const server = http.createServer()
  server.listen(AUTH_SERVER_PORT)

  const authUrl = oauth2Client.generateAuthUrl({ access_type: 'offline', scope: AUTH_SCOPES })

  logger('info', `Please visit this URL to authenticate: ${authUrl}`)

  open(authUrl)

  server.on('request', async (req, res) => {
    if (!req.url?.startsWith('/oauth2callback')) return

    const url = new URL(req.url, `http://localhost:${AUTH_SERVER_PORT}`)
    const code = url.searchParams.get('code')

    if (!code) {
      res.writeHead(400)
      res.end('No code provided')
      reject(new Error('No code provided'))
      return
    }

    try {
      const { tokens } = await oauth2Client.getToken(code)
      oauth2Client.setCredentials(tokens)
      fs.writeFileSync(GMAIL_CREDENTIALS_PATH, JSON.stringify(tokens, null, 2))

      res.writeHead(200)
      res.end('Authentication successful! You can close this window.')
      server.close()
      resolve(void 0)
    } catch (error: any) {
      res.writeHead(500)
      res.end('Authentication failed')
      reject(error)
    }
  })
})

export const validateCredentials = async (oauth2Client: OAuth2Client) => {
  try {
    const { credentials } = oauth2Client
    if (!credentials) {
      logger('info', 'No credentials found, please re-authenticate')
      return false
    }

    const currentTime = Date.now()
    const expiryDate = credentials.expiry_date
    const needsRefresh = !expiryDate || expiryDate <= currentTime

    if (!needsRefresh) {
      logger('info', 'Credentials are valid')
      return true
    }

    if (!credentials.refresh_token) {
      logger('info', 'No refresh token found, please re-authenticate')
      return false
    }

    const timeUntilExpiry = expiryDate ? (expiryDate - currentTime) : 0
    logger('info', `Access token is ${timeUntilExpiry > 0 ? 'expiring in ' + timeUntilExpiry + ' seconds' : 'expired'}, refreshing token`)

    const { credentials: tokens } = await oauth2Client.refreshAccessToken()
    oauth2Client.setCredentials(tokens)

    fs.writeFileSync(GMAIL_CREDENTIALS_PATH, JSON.stringify(tokens, null, 2))
    logger('info', 'Successfully refreshed and saved new credentials')
    return true
  } catch (error: any) { 
    logger('error', 'Error validating credentials', { error: error.message })
    return false
  }
}
