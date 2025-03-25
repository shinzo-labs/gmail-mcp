#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { z } from "zod"
import { google } from 'googleapis'
import { OAuth2Client } from 'google-auth-library'
import fs from 'fs'
import path from 'path'
import os from 'os'
import http from 'http'
import open from 'open'

const server = new McpServer({
  name: "Gmail-MCP",
  version: "1.0.0",
  description: "An expansive MCP for the Gmail API"
})

const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp')
const LOG_PATH = process.env.LOG_PATH || path.join(CONFIG_DIR, 'gmail-mcp.log')
const GMAIL_OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json')
const GMAIL_CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json')
const AUTH_SCOPES = [
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/gmail.compose',
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/gmail.settings.basic',
  'https://www.googleapis.com/auth/gmail.settings.sharing'
]

const logJson = (type, message, data = null) => {
  const log = { timestamp: new Date().toISOString(), type, message }
  if (data) log.data = data

  try {
    fs.appendFileSync(LOG_PATH, JSON.stringify(log) + '\n')
  } catch (error) {
    console.error('Error writing to log file:', error.message)
  }
}

const logJsonAndThrow = (message, data = null) => {
  logJson('error', message, data)
  throw new Error(message)
}

const createOAuth2Client = () => {
  logJson('info', 'Starting OAuth2Client creation')
  
  let keys = null

  if (!fs.existsSync(GMAIL_OAUTH_PATH)) {
    logJsonAndThrow(`OAuth2 keys file not found`, { path: GMAIL_OAUTH_PATH })
  }

  try {
    const keysContent = fs.readFileSync(GMAIL_OAUTH_PATH, 'utf8')
    const parsedKeys = JSON.parse(keysContent)
    keys = parsedKeys.installed
  } catch (error) {
    logJsonAndThrow(`Failed to read OAuth keys: ${error.message}`)
  }

  if (!keys || !keys.client_id || !keys.client_secret) {
    logJsonAndThrow(`Invalid OAuth keys format`, keys)
  }

  logJson('info', 'Creating OAuth2Client with credentials')

  const oauth2Client = new OAuth2Client({
    clientId: keys.client_id,
    clientSecret: keys.client_secret,
    redirectUri: 'http://localhost:3000/oauth2callback'
  })

  if (fs.existsSync(GMAIL_CREDENTIALS_PATH)) {
    logJson('info', 'Found existing credentials file', { path: GMAIL_CREDENTIALS_PATH })
    try {
      const credentials = JSON.parse(fs.readFileSync(GMAIL_CREDENTIALS_PATH, 'utf8'))
      oauth2Client.setCredentials(credentials)
      logJson('info', 'Successfully loaded existing credentials')
    } catch (error) {
      // Don't throw here, just continue without credentials
      logJson('error', 'Failed to read or parse credentials file', { error: error.message })
    }
  } else {
    logJson('info', 'No existing credentials file found', { path: GMAIL_CREDENTIALS_PATH })
  }

  return oauth2Client
}

const authenticate = async () => {
  const oauth2Client = createOAuth2Client()
  const credentials = oauth2Client.credentials

  if (credentials && credentials.access_token) {
    logJson('info', 'Valid credentials found, skipping authentication flow')
    return
  }

  return new Promise((resolve, reject) => {
    const server = http.createServer()
    server.listen(3000)

    const authUrl = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: AUTH_SCOPES
    })

    console.log('Please visit this URL to authenticate:', authUrl)
    open(authUrl)

    server.on('request', async (req, res) => {
      if (!req.url?.startsWith('/oauth2callback')) return

      const url = new URL(req.url, 'http://localhost:3000')
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
        resolve()
      } catch (error) {
        res.writeHead(500)
        res.end('Authentication failed')
        reject(error)
      }
    })
  })
}

const oauth2Client = createOAuth2Client()
await authenticate(oauth2Client)

if (process.argv[2] === 'auth') process.exit(0)

const gmail = google.gmail({ version: 'v1', auth: oauth2Client })

const ensureValidCredentials = async () => {
  if (!oauth2Client) logJsonAndThrow('OAuth2 client not initialized. Please check your credentials.')

  const credentials = oauth2Client.credentials
  if (!credentials || !credentials.access_token) {
    logJson('info', 'No credentials found, starting authentication flow')
    try {
      await authenticate(oauth2Client)
      logJson('info', 'Authentication completed successfully')
    } catch (error) { logJsonAndThrow(`Authentication failed, you may need to run "npx @shinzolabs/gmail-mcp auth" to authenticate: ${error.message}`) }
  }

  try {
    const expiryDate = credentials.expiry_date
    const currentTime = Date.now()
    const isExpired = expiryDate ? expiryDate <= currentTime : true

    if (!isExpired) { logJson('info', 'Credentials are still valid'); return }
    if (!credentials.refresh_token) logJsonAndThrow('No refresh token found, please re-authenticate')

    const timeUntilExpiry = expiryDate ? (expiryDate - currentTime) : 0
    logJson('info', `Access token is ${isExpired ? 'expired' : 'expiring in ' + timeUntilExpiry + ' seconds'}, refreshing token`)

    const { credentials: newCredentials } = await oauth2Client.refreshToken(credentials.refresh_token)
    const mergedCredentials = { ...newCredentials, refresh_token: credentials.refresh_token }
    oauth2Client.setCredentials(mergedCredentials)
    
    fs.writeFileSync(GMAIL_CREDENTIALS_PATH, JSON.stringify(mergedCredentials, null, 2))
    logJson('info', 'Successfully refreshed and saved new credentials')
  } catch (error) { logJsonAndThrow(`Error validating credentials: ${error.message}`) }
}

const formatResponse = (messageOrData, status = 200) => ({
  content: [{ type: "text", text: JSON.stringify(
    typeof messageOrData === 'string' ? { error: messageOrData, status } : messageOrData
  )}]
})

const callEndpoint = async (endpoint, params = {}, method = 'GET', body = null) => {
  logJson('info', 'Starting API request', { endpoint, params })
  
  await ensureValidCredentials()
  logJson('info', 'Credentials validated')

  const parts = endpoint.split('/')
  let resource = parts[3]
  let resourceMethod = 'list'

  if (resource === 'settings') {
    resource = `${resource}.${parts[4]}`
    resourceMethod = parts[5] || 'list'
  } else {
    if (method === 'GET') {
      resourceMethod = parts.length > 4 ? 'get' : 'list'
    } else if (method === 'POST') {
      if (endpoint.includes('/modify')) {
        resourceMethod = 'modify'
      } else if (endpoint.includes('/trash')) {
        resourceMethod = 'trash'
      } else if (endpoint.includes('/untrash')) {
        resourceMethod = 'untrash'
      } else if (endpoint.includes('/send')) {
        resourceMethod = 'send'
      } else if (endpoint.includes('/import')) {
        resourceMethod = 'import'
      } else if (endpoint.includes('/watch')) {
        resourceMethod = 'watch'
      } else if (endpoint.includes('/stop')) {
        resourceMethod = 'stop'
      } else if (endpoint.includes('/verify')) {
        resourceMethod = 'verify'
      } else if (endpoint.includes('/setDefault')) {
        resourceMethod = 'setDefault'
      } else {
        resourceMethod = 'create'
      }
    } else if (method === 'PUT') {
      resourceMethod = 'update'
    } else if (method === 'PATCH') {
      resourceMethod = 'patch'
    } else if (method === 'DELETE') {
      resourceMethod = 'delete'
    }
  }

  // Handle IDs in the endpoint
  if (parts.length > 4) {
    if (parts.length > 6 && parts[5] === 'attachments') {
      params.messageId = parts[4]
      params.id = parts[6]
      resource = 'messages.attachments'
    } else {
      params.id = parts[4]
    }
  }

  const requestParams = { userId: 'me', ...params }

  if (body) Object.assign(requestParams, body)

  try {
    logJson('info', 'Making API call', { resource, resourceMethod, params: requestParams })
    
    if (!gmail.users[resource]) {
      logJsonAndThrow(`Invalid API resource: users.${resource}`)
    }

    if (!gmail.users[resource][resourceMethod]) {
      logJsonAndThrow(`Invalid API method: users.${resource}.${resourceMethod}`)
    }

    const response = await gmail.users[resource][resourceMethod](requestParams)
    logJson('info', 'API call successful')
    return response.data
  } catch (error) {
    logJsonAndThrow(`API request failed: ${error.message}`)
  }
}

const handleEndpoint = async (apiCall) => {
  logJson('info', 'Starting endpoint handler')
  try {
    const result = await apiCall()
    logJson('info', 'Endpoint handler completed successfully')
    return result
  } catch (error) { logJsonAndThrow(`Endpoint handler failed: ${error.message}`) }
}

// Helper function to extract email content from message parts
const extractEmailContent = (part, path = '', options = { includeHeaders: false, includeBodyHtml: false }) => {
  let text = '', html = '', headers = []

  if (!part) {
    logJson('debug', 'No part provided to extractEmailContent', { path })
    return { text, html, headers }
  }

  if (part.mimeType === 'text/plain' && part.body?.data) {
    text = Buffer.from(part.body.data, 'base64').toString('utf-8')
    logJson('debug', 'Extracted plain text content', { path, originalSize: part.body.data.length, decodedSize: text.length })
  } else if (part.mimeType === 'text/html' && part.body?.data) {
    html = Buffer.from(part.body.data, 'base64').toString('utf-8')
    logJson('debug', 'Extracted HTML content', { path, originalSize: part.body.data.length, decodedSize: html.length })
  }

  if (part.parts) {
    logJson('debug', 'Processing child parts', { path, numParts: part.parts.length })
    
    part.parts.forEach((subpart, index) => {
      const subPath = `${path}/part${index}`
      const { text: subText, html: subHtml } = extractEmailContent(subpart, subPath, options)
      if (subText) text += subText
      if (subHtml) html += subHtml
    })

    logJson('debug', 'Finished processing child parts', { path, finalTextLength: text.length, finalHtmlLength: html.length })
  }

  return { text, html: options.includeBodyHtml ? html : undefined, headers: options.includeHeaders ? part.headers : undefined }
}

// Helper function to process attachments recursively
const processAttachments = (part, attachments = [], path = '') => {
  if (!part) {
    logJson('debug', 'No part provided to processAttachments', { path })
    return attachments
  }

  logJson('debug', 'Processing part for attachments', {
    path,
    mimeType: part.mimeType,
    hasBody: !!part.body,
    bodySize: part.body?.size || 0,
    hasAttachmentId: !!part.body?.attachmentId,
    filename: part.filename,
    hasParts: !!part.parts
  })

  if (part.body?.attachmentId) {
    const attachment = {
      id: part.body.attachmentId,
      filename: part.filename || `attachment-${part.body.attachmentId}`,
      mimeType: part.mimeType || 'application/octet-stream',
      size: part.body.size || 0
    }
    
    logJson('debug', 'Found attachment', { path, ...attachment })
    
    attachments.push(attachment)
  }

  if (part.parts) {
    logJson('debug', 'Processing child parts for attachments', {
      path,
      numParts: part.parts.length
    })
    
    part.parts.forEach((subpart, index) => {
      processAttachments(subpart, attachments, `${path}/part${index}`)
    })

    logJson('debug', 'Finished processing child parts for attachments', {
      path,
      totalAttachments: attachments.length
    })
  }

  return attachments
}

server.tool("create_draft",
  "Create a draft email in Gmail",
  {
    message: z.object({
      raw: z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format"),
      threadId: z.string().optional().describe("The thread ID of the message"),
      labelIds: z.array(z.string()).optional().describe("List of label IDs to apply to the message"),
      to: z.array(z.string()).optional().describe("Recipients in the To field"),
      cc: z.array(z.string()).optional().describe("Recipients in the CC field"),
      bcc: z.array(z.string()).optional().describe("Recipients in the BCC field"),
      subject: z.string().optional().describe("Subject of the email"),
      body: z.string().optional().describe("Body content of the email"),
      attachments: z.array(z.object({
        filename: z.string().describe("Name of the attachment"),
        data: z.string().describe("Base64 encoded attachment data"),
        mimeType: z.string().describe("MIME type of the attachment")
      })).optional().describe("File attachments")
    }).describe("The message to be created as a draft")
  },
  async (params) => {
    return handleEndpoint(async () => {
      // Convert the user-friendly format to Gmail API format
      const message = {
        raw: params.message.raw || Buffer.from(
          `${params.message.to ? `To: ${params.message.to.join(', ')}\n` : ''}` +
          `${params.message.cc ? `Cc: ${params.message.cc.join(', ')}\n` : ''}` +
          `${params.message.bcc ? `Bcc: ${params.message.bcc.join(', ')}\n` : ''}` +
          `${params.message.subject ? `Subject: ${params.message.subject}\n` : ''}` +
          `\n${params.message.body || ''}`
        ).toString('base64url'),
        threadId: params.message.threadId,
        labelIds: params.message.labelIds
      }

      const data = await callEndpoint(
        '/users/me/drafts',
        {},
        'POST',
        { message }
      )
      return formatResponse(data)
    })
  }
)

server.tool("send_message",
  "Send an email message to specified recipients",
  {
    message: z.object({
      raw: z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format"),
      threadId: z.string().optional().describe("The thread ID of the message"),
      labelIds: z.array(z.string()).optional().describe("List of label IDs to apply to the message"),
      to: z.array(z.string()).optional().describe("Recipients in the To field"),
      cc: z.array(z.string()).optional().describe("Recipients in the CC field"),
      bcc: z.array(z.string()).optional().describe("Recipients in the BCC field"),
      subject: z.string().optional().describe("Subject of the email"),
      body: z.string().optional().describe("Body content of the email"),
      attachments: z.array(z.object({
        filename: z.string().describe("Name of the attachment"),
        data: z.string().describe("Base64 encoded attachment data"),
        mimeType: z.string().describe("MIME type of the attachment")
      })).optional().describe("File attachments")
    }).describe("The message to be sent")
  },
  async (params) => {
    return handleEndpoint(async () => {
      // Convert the user-friendly format to Gmail API format
      const message = {
        raw: params.message.raw || Buffer.from(
          `${params.message.to ? `To: ${params.message.to.join(', ')}\n` : ''}` +
          `${params.message.cc ? `Cc: ${params.message.cc.join(', ')}\n` : ''}` +
          `${params.message.bcc ? `Bcc: ${params.message.bcc.join(', ')}\n` : ''}` +
          `${params.message.subject ? `Subject: ${params.message.subject}\n` : ''}` +
          `\n${params.message.body || ''}`
        ).toString('base64url'),
        threadId: params.message.threadId,
        labelIds: params.message.labelIds
      }

      const data = await callEndpoint(
        '/users/me/messages/send',
        {},
        'POST',
        { message }
      )
      return formatResponse(data)
    })
  }
)

server.tool("list_messages",
  "List messages in the user's mailbox with optional filtering",
  {
    maxResults: z.number().optional().describe("Maximum number of messages to return. Accepts values between 1-500"),
    pageToken: z.string().optional().describe("Page token to retrieve a specific page of results"),
    q: z.string().optional().describe("Only return messages matching the specified query. Supports the same query format as the Gmail search box"),
    labelIds: z.array(z.string()).optional().describe("Only return messages with labels that match all of the specified label IDs"),
    includeSpamTrash: z.boolean().optional().describe("Include messages from SPAM and TRASH in the results"),
    includeHeaders: z.boolean().optional().describe("Whether to include headers from the e-mail for all components"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
  },
  async (params) => {
    logJson('info', 'Starting list_messages', { params })
    return handleEndpoint(async () => {
      logJson('info', 'Processing list_messages request')
      let data = await callEndpoint(
        '/users/me/messages',
        {
          maxResults: params.maxResults,
          pageToken: params.pageToken,
          q: params.q,
          labelIds: params.labelIds?.join(','),
          format: 'full'
        }
      )

      if (data.messages) {
        data.messages = data.messages.map(message => {
          if (message.payload) {
            const { text, html, headers } = extractEmailContent(message.payload, '', {
              includeHeaders: params.includeHeaders,
              includeBodyHtml: params.includeBodyHtml
            })

            const attachments = processAttachments(message.payload)

            let parts = (message.payload.parts || []).map((part) => {
              const { text, html, headers } = extractEmailContent(part, '', {
                includeHeaders: params.includeHeaders,
                includeBodyHtml: params.includeBodyHtml
              })
              return {
                ...part,
                body: {
                  text,
                  html,
                  headers
                }
              }
            })

            return {
              ...message,
              payload: {
                ...message.payload,
                body: { 
                  text, 
                  html, 
                  headers,
                  attachments: attachments.length > 0 ? attachments : null 
                },
                parts
              }
            }
          }
          return message
        })
      }

      logJson('info', 'List messages request completed')
      return formatResponse(data)
    })
  }
)

server.tool("get_message",
  "Get a specific message by ID with format options",
  {
    id: z.string().describe("The ID of the message to retrieve"),
    includeHeaders: z.boolean().optional().describe("Whether to include headers from the e-mail for all components"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
  },
  async (params) => {
    return handleEndpoint(async () => {
      let data = await callEndpoint(
        `/users/me/messages/${params.id}`,
        { format: 'full' }
      )

      if (data.payload) {
        const { text, html, headers } = extractEmailContent(data.payload, '', {
          includeHeaders: params.includeHeaders,
          includeBodyHtml: params.includeBodyHtml
        })
        
        const attachments = processAttachments(data.payload)

        let parts = (data.payload.parts || []).map((part) => {
          const { text, html, headers } = extractEmailContent(part, '', {
            includeHeaders: params.includeHeaders,
            includeBodyHtml: params.includeBodyHtml
          })
          return { ...part, body: { text, html, headers } }
        })

        data = {
          ...data,
          payload: {
            ...data.payload,
            body: { 
              text, 
              html, 
              headers,
              attachments: attachments.length > 0 ? attachments : null 
            },
            parts
          }
        }
      }

      return formatResponse(data)
    })
  }
)

server.tool("modify_message",
  "Modify the labels on a message",
  {
    id: z.string().describe("The ID of the message to modify"),
    addLabelIds: z.array(z.string()).optional().describe("A list of label IDs to add to the message"),
    removeLabelIds: z.array(z.string()).optional().describe("A list of label IDs to remove from the message")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/messages/${params.id}/modify`,
        {},
        'POST',
        {
          addLabelIds: params.addLabelIds,
          removeLabelIds: params.removeLabelIds
        }
      )
      return formatResponse(data)
    })
  }
)

server.tool("trash_message",
  "Move a message to the trash",
  {
    id: z.string().describe("The ID of the message to move to trash")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/messages/${params.id}/trash`,
        {},
        'POST'
      )
      return formatResponse(data)
    })
  }
)

server.tool("untrash_message",
  "Remove a message from the trash",
  {
    id: z.string().describe("The ID of the message to remove from trash")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/messages/${params.id}/untrash`,
        {},
        'POST'
      )
      return formatResponse(data)
    })
  }
)

server.tool("batch_modify_messages",
  "Modify the labels on multiple messages",
  {
    ids: z.array(z.string()).describe("The IDs of the messages to modify"),
    addLabelIds: z.array(z.string()).optional().describe("A list of label IDs to add to the messages"),
    removeLabelIds: z.array(z.string()).optional().describe("A list of label IDs to remove from the messages")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/messages/batchModify',
        {},
        'POST',
        {
          ids: params.ids,
          addLabelIds: params.addLabelIds,
          removeLabelIds: params.removeLabelIds
        }
      )
      return formatResponse(data)
    })
  }
)

server.tool("batch_delete_messages",
  "Delete multiple messages",
  {
    ids: z.array(z.string()).describe("The IDs of the messages to delete")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/messages/batchDelete',
        {},
        'POST',
        {
          ids: params.ids
        }
      )
      return formatResponse(data)
    })
  }
)

server.tool("list_labels",
  "List all labels in the user's mailbox",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/labels'
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_label",
  "Get a specific label by ID",
  {
    id: z.string().describe("The ID of the label to retrieve")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/labels/${params.id}`
      )
      return formatResponse(data)
    })
  }
)

server.tool("create_label",
  "Create a new label",
  {
    name: z.string().describe("The display name of the label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("The visibility of messages with this label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("The visibility of the label in the label list"),
    color: z.object({
      textColor: z.string().describe("The text color of the label as hex string"),
      backgroundColor: z.string().describe("The background color of the label as hex string")
    }).optional().describe("The color settings for the label")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/labels',
        {},
        'POST',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("update_label",
  "Update an existing label",
  {
    id: z.string().describe("The ID of the label to update"),
    name: z.string().optional().describe("The display name of the label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("The visibility of messages with this label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("The visibility of the label in the label list"),
    color: z.object({
      textColor: z.string().describe("The text color of the label as hex string"),
      backgroundColor: z.string().describe("The background color of the label as hex string")
    }).optional().describe("The color settings for the label")
  },
  async (params) => {
    const { id, ...labelData } = params
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/labels/${id}`,
        {},
        'PUT',
        labelData
      )
      return formatResponse(data)
    })
  }
)

server.tool("patch_label",
  "Patch an existing label (partial update)",
  {
    id: z.string().describe("The ID of the label to patch"),
    name: z.string().optional().describe("The display name of the label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("The visibility of messages with this label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("The visibility of the label in the label list"),
    color: z.object({
      textColor: z.string().describe("The text color of the label as hex string"),
      backgroundColor: z.string().describe("The background color of the label as hex string")
    }).optional().describe("The color settings for the label")
  },
  async (params) => {
    const { id, ...labelData } = params
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/labels/${id}`,
        {},
        'PATCH',
        labelData
      )
      return formatResponse(data)
    })
  }
)

server.tool("delete_label",
  "Delete a label",
  {
    id: z.string().describe("The ID of the label to delete")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/labels/${params.id}`,
        {},
        'DELETE'
      )
      return formatResponse(data)
    })
  }
)

server.tool("list_threads",
  "List threads in the user's mailbox",
  {
    maxResults: z.number().optional().describe("Maximum number of threads to return"),
    pageToken: z.string().optional().describe("Page token to retrieve a specific page of results"),
    q: z.string().optional().describe("Only return threads matching the specified query"),
    labelIds: z.array(z.string()).optional().describe("Only return threads with labels that match all of the specified label IDs"),
    includeSpamTrash: z.boolean().optional().describe("Include threads from SPAM and TRASH in the results")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/threads',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_thread",
  "Get a specific thread by ID",
  {
    id: z.string().describe("The ID of the thread to retrieve"),
    includeHeaders: z.boolean().optional().describe("Whether to include headers from the e-mail for all components"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
  },
  async (params) => {
    return handleEndpoint(async () => {
      let data = await callEndpoint(
        `/users/me/threads/${params.id}`,
        { format: 'full' }
      )

      if (data.messages) {
        data.messages = data.messages.map(message => {
          if (message.payload) {
            const { text, html, headers } = extractEmailContent(message.payload, '', {
              includeHeaders: params.includeHeaders,
              includeBodyHtml: params.includeBodyHtml
            })
            
            const attachments = processAttachments(message.payload)

            let parts = (message.payload.parts || []).map((part) => {
              const { text, html, headers } = extractEmailContent(part, '', {
                includeHeaders: params.includeHeaders,
                includeBodyHtml: params.includeBodyHtml
              })
              return {
                ...part,
                body: {
                  text,
                  html,
                  headers
                }
              }
            })

            return {
              ...message,
              payload: {
                ...message.payload,
                body: { 
                  text, 
                  html, 
                  headers,
                  attachments: attachments.length > 0 ? attachments : null 
                },
                parts
              }
            }
          }
          return message
        })
      }

      return formatResponse(data)
    })
  }
)

server.tool("modify_thread",
  "Modify the labels applied to a thread",
  {
    id: z.string().describe("The ID of the thread to modify"),
    addLabelIds: z.array(z.string()).optional().describe("A list of label IDs to add to the thread"),
    removeLabelIds: z.array(z.string()).optional().describe("A list of label IDs to remove from the thread")
  },
  async (params) => {
    const { id, ...threadData } = params
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/threads/${id}/modify`,
        {},
        'POST',
        threadData
      )
      return formatResponse(data)
    })
  }
)

server.tool("trash_thread",
  "Move a thread to the trash",
  {
    id: z.string().describe("The ID of the thread to move to trash")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/threads/${params.id}/trash`,
        {},
        'POST'
      )
      return formatResponse(data)
    })
  }
)

server.tool("untrash_thread",
  "Remove a thread from the trash",
  {
    id: z.string().describe("The ID of the thread to remove from trash")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/threads/${params.id}/untrash`,
        {},
        'POST'
      )
      return formatResponse(data)
    })
  }
)

server.tool("delete_thread",
  "Delete a thread",
  {
    id: z.string().describe("The ID of the thread to delete")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/threads/${params.id}`,
        {},
        'DELETE'
      )
      return formatResponse(data)
    })
  }
)

server.tool("list_drafts",
  "List drafts in the user's mailbox",
  {
    maxResults: z.number().optional().describe("Maximum number of drafts to return. Accepts values between 1-500"),
    pageToken: z.string().optional().describe("Page token to retrieve a specific page of results"),
    q: z.string().optional().describe("Only return drafts matching the specified query. Supports the same query format as the Gmail search box"),
    includeSpamTrash: z.boolean().optional().describe("Include drafts from SPAM and TRASH in the results")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/drafts',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_draft",
  "Get a specific draft by ID",
  {
    id: z.string().describe("The ID of the draft to retrieve")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/drafts/${params.id}`,
        { format: 'full' }
      )
      return formatResponse(data)
    })
  }
)

server.tool("update_draft",
  "Replace a draft's content",
  {
    id: z.string().describe("The ID of the draft to update"),
    message: z.object({
      raw: z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format"),
      threadId: z.string().optional().describe("The thread ID of the message"),
      labelIds: z.array(z.string()).optional().describe("List of label IDs to apply to the message"),
      to: z.array(z.string()).optional().describe("Recipients in the To field"),
      cc: z.array(z.string()).optional().describe("Recipients in the CC field"),
      bcc: z.array(z.string()).optional().describe("Recipients in the BCC field"),
      subject: z.string().optional().describe("Subject of the email"),
      body: z.string().optional().describe("Body content of the email"),
      attachments: z.array(z.object({
        filename: z.string().describe("Name of the attachment"),
        data: z.string().describe("Base64 encoded attachment data"),
        mimeType: z.string().describe("MIME type of the attachment")
      })).optional().describe("File attachments")
    }).describe("The updated message content")
  },
  async (params) => {
    return handleEndpoint(async () => {
      // Convert the user-friendly format to Gmail API format
      const message = {
        raw: params.message.raw || Buffer.from(
          `${params.message.to ? `To: ${params.message.to.join(', ')}\n` : ''}` +
          `${params.message.cc ? `Cc: ${params.message.cc.join(', ')}\n` : ''}` +
          `${params.message.bcc ? `Bcc: ${params.message.bcc.join(', ')}\n` : ''}` +
          `${params.message.subject ? `Subject: ${params.message.subject}\n` : ''}` +
          `\n${params.message.body || ''}`
        ).toString('base64url'),
        threadId: params.message.threadId,
        labelIds: params.message.labelIds
      }

      const data = await callEndpoint(
        `/users/me/drafts/${params.id}`,
        {},
        'PUT',
        { message }
      )
      return formatResponse(data)
    })
  }
)

server.tool("delete_draft",
  "Delete a draft",
  {
    id: z.string().describe("The ID of the draft to delete")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/drafts/${params.id}`,
        {},
        'DELETE'
      )
      return formatResponse(data)
    })
  }
)

server.tool("send_draft",
  "Send an existing draft",
  {
    id: z.string().describe("The ID of the draft to send")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/drafts/send',
        {},
        'POST',
        { id: params.id }
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_auto_forwarding",
  "Get the auto-forwarding setting for the account",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/autoForwarding'
      )
      return formatResponse(data)
    })
  }
)

server.tool("update_auto_forwarding",
  "Update the auto-forwarding setting for the account",
  {
    enabled: z.boolean().describe("Whether all incoming mail is automatically forwarded to another address"),
    emailAddress: z.string().describe("Email address to which messages should be forwarded"),
    disposition: z.enum(['leaveInInbox', 'archive', 'trash', 'markRead']).describe("The state in which to leave messages after auto-forwarding")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/autoForwarding',
        {},
        'PUT',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_imap",
  "Get IMAP settings",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/imap'
      )
      return formatResponse(data)
    })
  }
)

server.tool("update_imap",
  "Update IMAP settings",
  {
    enabled: z.boolean().describe("Whether IMAP is enabled for the account"),
    expungeBehavior: z.enum(['archive', 'trash', 'deleteForever']).optional().describe("The action that will be executed on a message when it is marked as deleted and expunged from the last visible IMAP folder"),
    maxFolderSize: z.number().optional().describe("An optional limit on the number of messages that an IMAP folder may contain")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/imap',
        {},
        'PUT',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_pop",
  "Get POP settings",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/pop'
      )
      return formatResponse(data)
    })
  }
)

server.tool("update_pop",
  "Update POP settings",
  {
    accessWindow: z.enum(['disabled', 'allMail', 'fromNowOn']).describe("The range of messages which are accessible via POP"),
    disposition: z.enum(['leaveInInbox', 'archive', 'trash', 'markRead']).describe("The action to be taken for messages after they are accessed via POP")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/pop',
        {},
        'PUT',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_vacation",
  "Get vacation responder settings",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/vacation'
      )
      return formatResponse(data)
    })
  }
)

server.tool("update_vacation",
  "Update vacation responder settings",
  {
    enableAutoReply: z.boolean().describe("Whether the vacation responder is enabled"),
    responseSubject: z.string().optional().describe("Optional subject line for the vacation responder auto-reply"),
    responseBodyPlainText: z.string().describe("Response body in plain text format"),
    restrictToContacts: z.boolean().optional().describe("Whether responses are only sent to contacts"),
    restrictToDomain: z.boolean().optional().describe("Whether responses are only sent to users in the same domain"),
    startTime: z.string().optional().describe("Start time for sending auto-replies (epoch ms)"),
    endTime: z.string().optional().describe("End time for sending auto-replies (epoch ms)")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/vacation',
        {},
        'PUT',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_language",
  "Get language settings",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/language'
      )
      return formatResponse(data)
    })
  }
)

server.tool("update_language",
  "Update language settings",
  {
    displayLanguage: z.string().describe("The language to display Gmail in, formatted as an RFC 3066 Language Tag")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/language',
        {},
        'PUT',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("list_delegates",
  "Lists the delegates for the specified account",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/delegates'
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_delegate",
  "Gets the specified delegate",
  {
    delegateEmail: z.string().describe("The email address of the delegate to retrieve")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/delegates/${params.delegateEmail}`
      )
      return formatResponse(data)
    })
  }
)

server.tool("add_delegate",
  "Adds a delegate to the specified account",
  {
    delegateEmail: z.string().describe("Email address of delegate to add")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/delegates',
        {},
        'POST',
        { delegateEmail: params.delegateEmail }
      )
      return formatResponse(data)
    })
  }
)

server.tool("remove_delegate",
  "Removes the specified delegate",
  {
    delegateEmail: z.string().describe("Email address of delegate to remove")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/delegates/${params.delegateEmail}`,
        {},
        'DELETE'
      )
      return formatResponse(data)
    })
  }
)

server.tool("list_filters",
  "Lists the message filters of a Gmail user",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/filters'
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_filter",
  "Gets a filter",
  {
    id: z.string().describe("The ID of the filter to be fetched")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/filters/${params.id}`
      )
      return formatResponse(data)
    })
  }
)

server.tool("create_filter",
  "Creates a filter",
  {
    criteria: z.object({
      from: z.string().optional().describe("The sender's display name or email address"),
      to: z.string().optional().describe("The recipient's display name or email address"),
      subject: z.string().optional().describe("Case-insensitive phrase in the message's subject"),
      query: z.string().optional().describe("A Gmail search query that specifies the filter's criteria"),
      negatedQuery: z.string().optional().describe("A Gmail search query that specifies criteria the message must not match"),
      hasAttachment: z.boolean().optional().describe("Whether the message has any attachment"),
      excludeChats: z.boolean().optional().describe("Whether the response should exclude chats"),
      size: z.number().optional().describe("The size of the entire RFC822 message in bytes"),
      sizeComparison: z.enum(['smaller', 'larger']).optional().describe("How the message size in bytes should be in relation to the size field")
    }).describe("Filter criteria"),
    action: z.object({
      addLabelIds: z.array(z.string()).optional().describe("List of labels to add to messages"),
      removeLabelIds: z.array(z.string()).optional().describe("List of labels to remove from messages"),
      forward: z.string().optional().describe("Email address that the message should be forwarded to")
    }).describe("Actions to perform on messages matching the criteria")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/filters',
        {},
        'POST',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("delete_filter",
  "Deletes a filter",
  {
    id: z.string().describe("The ID of the filter to be deleted")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/filters/${params.id}`,
        {},
        'DELETE'
      )
      return formatResponse(data)
    })
  }
)

server.tool("list_forwarding_addresses",
  "Lists the forwarding addresses for the specified account",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/forwardingAddresses'
      )
      return formatResponse(data)
    })
  }
)

server.tool("create_forwarding_address",
  "Creates a forwarding address",
  {
    forwardingEmail: z.string().describe("An email address to which messages can be forwarded")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/forwardingAddresses',
        {},
        'POST',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_forwarding_address",
  "Gets the specified forwarding address",
  {
    forwardingEmail: z.string().describe("The forwarding address to be retrieved")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/forwardingAddresses/${params.forwardingEmail}`
      )
      return formatResponse(data)
    })
  }
)

server.tool("delete_forwarding_address",
  "Deletes the specified forwarding address",
  {
    forwardingEmail: z.string().describe("The forwarding address to be deleted")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/forwardingAddresses/${params.forwardingEmail}`,
        {},
        'DELETE'
      )
      return formatResponse(data)
    })
  }
)

server.tool("list_send_as",
  "Lists the send-as aliases for the specified account",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/sendAs'
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_send_as",
  "Gets the specified send-as alias",
  {
    sendAsEmail: z.string().describe("The send-as alias to be retrieved")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/sendAs/${params.sendAsEmail}`
      )
      return formatResponse(data)
    })
  }
)

server.tool("create_send_as",
  "Creates a custom send-as alias",
  {
    sendAsEmail: z.string().describe("The email address that appears in the 'From:' header"),
    displayName: z.string().optional().describe("A name that appears in the 'From:' header"),
    replyToAddress: z.string().optional().describe("An optional email address that is included in a 'Reply-To:' header"),
    signature: z.string().optional().describe("An optional HTML signature"),
    isPrimary: z.boolean().optional().describe("Whether this address is the primary address"),
    treatAsAlias: z.boolean().optional().describe("Whether Gmail should treat this address as an alias")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/settings/sendAs',
        {},
        'POST',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("update_send_as",
  "Updates a send-as alias",
  {
    sendAsEmail: z.string().describe("The send-as alias to be updated"),
    displayName: z.string().optional().describe("A name that appears in the 'From:' header"),
    replyToAddress: z.string().optional().describe("An optional email address that is included in a 'Reply-To:' header"),
    signature: z.string().optional().describe("An optional HTML signature"),
    isPrimary: z.boolean().optional().describe("Whether this address is the primary address"),
    treatAsAlias: z.boolean().optional().describe("Whether Gmail should treat this address as an alias")
  },
  async (params) => {
    const { sendAsEmail, ...updateData } = params
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/sendAs/${sendAsEmail}`,
        {},
        'PUT',
        updateData
      )
      return formatResponse(data)
    })
  }
)

server.tool("patch_send_as",
  "Patches the specified send-as alias",
  {
    sendAsEmail: z.string().describe("The send-as alias to be updated"),
    displayName: z.string().optional().describe("A name that appears in the 'From:' header"),
    replyToAddress: z.string().optional().describe("An optional email address that is included in a 'Reply-To:' header"),
    signature: z.string().optional().describe("An optional HTML signature"),
    isPrimary: z.boolean().optional().describe("Whether this address is the primary address"),
    treatAsAlias: z.boolean().optional().describe("Whether Gmail should treat this address as an alias")
  },
  async (params) => {
    const { sendAsEmail, ...patchData } = params
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/sendAs/${sendAsEmail}`,
        {},
        'PATCH',
        patchData
      )
      return formatResponse(data)
    })
  }
)

server.tool("verify_send_as",
  "Sends a verification email to the specified send-as alias",
  {
    sendAsEmail: z.string().describe("The send-as alias to be verified")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/sendAs/${params.sendAsEmail}/verify`,
        {},
        'POST'
      )
      return formatResponse(data)
    })
  }
)

server.tool("delete_send_as",
  "Deletes the specified send-as alias",
  {
    sendAsEmail: z.string().describe("The send-as alias to be deleted")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/sendAs/${params.sendAsEmail}`,
        {},
        'DELETE'
      )
      return formatResponse(data)
    })
  }
)

server.tool("list_smime_info",
  "Lists S/MIME configs for the specified send-as alias",
  {
    sendAsEmail: z.string().describe("The email address that appears in the 'From:' header")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/sendAs/${params.sendAsEmail}/smimeInfo`
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_smime_info",
  "Gets the specified S/MIME config for the specified send-as alias",
  {
    sendAsEmail: z.string().describe("The email address that appears in the 'From:' header"),
    id: z.string().describe("The immutable ID for the S/MIME config")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/sendAs/${params.sendAsEmail}/smimeInfo/${params.id}`
      )
      return formatResponse(data)
    })
  }
)

server.tool("insert_smime_info",
  "Insert (upload) the given S/MIME config for the specified send-as alias",
  {
    sendAsEmail: z.string().describe("The email address that appears in the 'From:' header"),
    encryptedKeyPassword: z.string().describe("Encrypted key password"),
    pkcs12: z.string().describe("PKCS#12 format containing a single private/public key pair and certificate chain")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/sendAs/${params.sendAsEmail}/smimeInfo`,
        {},
        'POST',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("set_default_smime_info",
  "Sets the default S/MIME config for the specified send-as alias",
  {
    sendAsEmail: z.string().describe("The email address that appears in the 'From:' header"),
    id: z.string().describe("The immutable ID for the S/MIME config")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/sendAs/${params.sendAsEmail}/smimeInfo/${params.id}/setDefault`,
        {},
        'POST'
      )
      return formatResponse(data)
    })
  }
)

server.tool("delete_smime_info",
  "Deletes the specified S/MIME config for the specified send-as alias",
  {
    sendAsEmail: z.string().describe("The email address that appears in the 'From:' header"),
    id: z.string().describe("The immutable ID for the S/MIME config")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/settings/sendAs/${params.sendAsEmail}/smimeInfo/${params.id}`,
        {},
        'DELETE'
      )
      return formatResponse(data)
    })
  }
)

server.tool("list_history",
  "List the history of all changes to the mailbox",
  {
    startHistoryId: z.string().describe("Required. Returns history records after this marker. Obtained from messages, threads or previous list history calls."),
    labelId: z.string().optional().describe("Only return messages with a label matching this ID"),
    maxResults: z.number().optional().describe("Maximum number of history records to return"),
    pageToken: z.string().optional().describe("Page token to retrieve a specific page of results"),
    historyTypes: z.array(z.enum(['messageAdded', 'messageDeleted', 'labelAdded', 'labelRemoved'])).optional().describe("History types to be returned by the function")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/history',
        {
          ...params,
          historyTypes: params.historyTypes?.join(',')
        }
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_profile",
  "Get the current user's Gmail profile",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/profile'
      )
      return formatResponse(data)
    })
  }
)

server.tool("stop_mail_watch",
  "Stop receiving push notifications for the given user mailbox",
  {},
  async () => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/stop',
        {},
        'POST'
      )
      return formatResponse(data)
    })
  }
)

server.tool("watch_mailbox",
  "Watch for changes to the user's mailbox",
  {
    topicName: z.string().describe("The name of the Cloud Pub/Sub topic to publish notifications to"),
    labelIds: z.array(z.string()).optional().describe("Label IDs to restrict notifications to"),
    labelFilterAction: z.enum(['include', 'exclude']).optional().describe("Whether to include or exclude the specified labels")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/watch',
        {},
        'POST',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_attachment",
  "Get a message attachment",
  {
    messageId: z.string().describe("ID of the message containing the attachment"),
    id: z.string().describe("The ID of the attachment"),
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/messages/${params.messageId}/attachments/${params.id}`
      )
      return formatResponse(data)
    })
  }
)

server.tool("delete_message",
  "Immediately and permanently delete a message",
  {
    id: z.string().describe("The ID of the message to delete")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        `/users/me/messages/${params.id}`,
        {},
        'DELETE'
      )
      return formatResponse(data)
    })
  }
)

server.tool("import_message",
  "Import a message into the mailbox",
  {
    raw: z.string().describe("The entire email message in base64url encoded RFC 2822 format"),
    internalDateSource: z.enum(['dateHeader', 'receivedTime']).optional().describe("Source for the message's internal date"),
    neverMarkSpam: z.boolean().optional().describe("Ignore spam classification"),
    processForCalendar: z.boolean().optional().describe("Process calendar invites in the email"),
    deleted: z.boolean().optional().describe("Mark the email as permanently deleted")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/messages/import',
        {},
        'POST',
        params
      )
      return formatResponse(data)
    })
  }
)

server.tool("insert_message",
  "Insert a message into the mailbox",
  {
    raw: z.string().describe("The entire email message in base64url encoded RFC 2822 format"),
    internalDateSource: z.enum(['dateHeader', 'receivedTime']).optional().describe("Source for the message's internal date"),
    deleted: z.boolean().optional().describe("Mark the email as permanently deleted")
  },
  async (params) => {
    return handleEndpoint(async () => {
      const data = await callEndpoint(
        '/users/me/messages',
        {},
        'POST',
        params
      )
      return formatResponse(data)
    })
  }
)
const transport = new StdioServerTransport()
await server.connect(transport)

