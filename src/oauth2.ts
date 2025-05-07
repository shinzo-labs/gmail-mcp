import { AUTH_SERVER_PORT, CLIENT_ID, CLIENT_SECRET, GMAIL_CREDENTIALS_PATH, GMAIL_OAUTH_PATH, REFRESH_TOKEN } from "./config.js"
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

const getEnvBasedCredentials = (queryConfig?: Record<string, any>) => {
  const clientId = queryConfig?.CLIENT_ID || CLIENT_ID
  const clientSecret = queryConfig?.CLIENT_SECRET || CLIENT_SECRET
  const refreshToken = queryConfig?.REFRESH_TOKEN || REFRESH_TOKEN

  if (!clientId || !clientSecret || !refreshToken) return null

  return { clientId, clientSecret, refreshToken }
}

const getFileBasedCredentials = () => {
  const oauthFilePresent = fs.existsSync(GMAIL_OAUTH_PATH)
  if (!oauthFilePresent) return null

  const keysContent = fs.readFileSync(GMAIL_OAUTH_PATH, 'utf8')
  const parsedKeys = JSON.parse(keysContent)

  const clientId = parsedKeys?.installed?.client_id || parsedKeys?.web?.client_id
  const clientSecret = parsedKeys?.installed?.client_secret || parsedKeys?.web?.client_secret

  let refreshToken = null
  if (fs.existsSync(GMAIL_CREDENTIALS_PATH)) {
    const gmailCredentialsFile = JSON.parse(fs.readFileSync(GMAIL_CREDENTIALS_PATH, 'utf8'))
    refreshToken = gmailCredentialsFile?.refresh_token
  }

  return { clientId, clientSecret, refreshToken }
}

export const createOAuth2Client = (queryConfig?: Record<string, any>) => {
  try {
    let credentials = getEnvBasedCredentials(queryConfig)

    if (!credentials) credentials = getFileBasedCredentials()

    const oauth2Client = new OAuth2Client({
      clientId: credentials?.clientId,
      clientSecret: credentials?.clientSecret,
      redirectUri: `http://localhost:${AUTH_SERVER_PORT}/oauth2callback`
    })

    if (credentials?.refreshToken) oauth2Client.setCredentials({ refresh_token: credentials.refreshToken })

    return oauth2Client
  } catch (error: any) {
    return null
  }
}

export const launchAuthServer = async (oauth2Client: OAuth2Client) => new Promise((resolve, reject) => {
  const server = http.createServer()
  server.listen(AUTH_SERVER_PORT)

  const authUrl = oauth2Client.generateAuthUrl({ access_type: 'offline', scope: AUTH_SCOPES })

  console.log(`Please visit this URL to authenticate: ${authUrl}`)

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
      res.end(`Authentication successful! Go to ${GMAIL_CREDENTIALS_PATH} to view your REFRESH_TOKEN. You can close this window.`)
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
    if (!credentials) return false

    const expiryDate = credentials.expiry_date
    const needsRefresh = !expiryDate || expiryDate <= Date.now()

    if (!needsRefresh) return true

    if (!credentials.refresh_token) return false

    const { credentials: tokens } = await oauth2Client.refreshAccessToken()
    oauth2Client.setCredentials(tokens)

    fs.writeFileSync(GMAIL_CREDENTIALS_PATH, JSON.stringify(tokens, null, 2))
    return true
  } catch (error: any) { 
    return false
  }
}
