#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { z } from "zod"
import { google } from 'googleapis'
import { logger } from "logger"
import { createOAuth2Client, launchAuthServer, validateCredentials } from "./oauth2"

type EndpointParams = {
  id?: string
  messageId?: string
  threadId?: string
  format?: string
  // [key: string]: string | number | boolean | null | undefined
}

type Message = {
  id: string
  threadId: string
  labelIds: string[]
  snippet: string
  historyId: string
  internalDate: string
  payload: MessagePart
  sizeEstimate: number
  raw: string
}

type MessagePartBody = {
  data?: string
  size?: number
  originalSize?: number // Custom Field
  attachmentId?: string
}

type MessagePartHeader = {
  name: string
  value: string
}

type MessagePart = {
  body: MessagePartBody
  parts?: MessagePart[]
  mimeType: string
  filename?: string
  headers: MessagePartHeader[]
}

type Draft = {
  id: string
  message: Message
}

type Thread = {
  id: string
  snippet: string
  historyId: string
  messages: Message[]
}

type NewMessage = {
  threadId?: string
  raw?: string
  to?: string
  cc?: string
  bcc?: string
  body?: string
}

const DEFAULT_HEADERS_LIST = [
  'Date',
  'From',
  'To',
  'Subject',
  'Message-ID',
  'In-Reply-To',
  'References'
]

const oauth2Client = createOAuth2Client()

if (process.argv[2] === 'auth') {
  await launchAuthServer(oauth2Client)
  process.exit(0)
}

const server = new McpServer({
  name: "Gmail-MCP",
  version: "1.0.0",
  description: "An expansive MCP for the Gmail API"
})

const gmail = google.gmail({ version: 'v1', auth: oauth2Client })

const formatResponse = (response: any) => ({
  content: [{ type: "text", text: JSON.stringify(response) }]
})

const callEndpoint = async (endpoint: string, params: EndpointParams, method = 'GET', body = null) => {
  logger('info', 'Starting API request', { endpoint, params })

  const credentialsAreValid = await validateCredentials(oauth2Client)
  if (!credentialsAreValid) throw new Error('No credentials found, you may need to run "npx @shinzolabs/gmail-mcp auth" to authenticate')

  // Example: '/users/me/messages/send'
  const parts = endpoint.split('/')
  const userId = parts[2]
  let resource = parts[3]
  let resourceMethod

  //TODO double-check this logic
  if (resource === 'settings') {
    resource += '.' + parts[4]
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

  const requestParams = { userId, ...params }

  if (body) Object.assign(requestParams, body)

  logger('info', 'Making API call', { resource, resourceMethod, params: requestParams })
  
  const resourceApi = gmail.users[resource as keyof typeof gmail.users]
  if (!resourceApi) throw new Error(`Invalid resource: ${resource}`)

  const gmailServiceCall = resourceApi[resourceMethod as keyof typeof resourceApi] as (params: any) => Promise<{ data: any }>
  if (!gmailServiceCall) throw new Error(`Invalid resource method: ${resource}.${resourceMethod}`)

  const { data } = await gmailServiceCall(requestParams)
  logger('info', 'API call successful')
  return data
}

const handleTool = async (apiCall: () => Promise<any>) => {
  logger('info', 'Starting tool handler')
  try {
    const result = await apiCall()
    logger('info', 'Tool execution completed successfully')
    return result
  } catch (error: any) {
    logger('error', `Tool execution failed: ${error.message}\n${error.stack}`)
    return `Tool execution failed: ${error.message}`
  }
}

const decodedBody = (body: MessagePartBody) => {
  if (!body?.data) return body

  logger('debug', 'Decoding body', body)
  const decodedData = Buffer.from(body.data, 'base64').toString('utf-8')
  const decodedBody: MessagePartBody = {
    data: decodedData,
    size: body.data.length,
    originalSize: body.data.length,
    attachmentId: body.attachmentId
  }
  logger('debug', 'Decoded body', decodedBody)
  return decodedBody
}

const processMessage = (messagePart: MessagePart, headersList = DEFAULT_HEADERS_LIST, includeBodyHtml = false): MessagePart => {
  if (messagePart.mimeType !== 'text/html' || includeBodyHtml) {
    messagePart.body = decodedBody(messagePart.body)
  }

  if (messagePart.parts) {
    messagePart.parts = messagePart.parts.map(part => processMessage(part, headersList, includeBodyHtml))
  }

  messagePart.headers = messagePart.headers.filter(header => headersList.includes(header.name))

  return messagePart
}

const getNestedHistory = (messagePart: MessagePart, level = 1): string => {
  if (messagePart.mimeType === 'text/plain' && messagePart.body?.data) {
    const { data } = decodedBody(messagePart.body)
    if (!data) return ''
    const prefix = '>' + ' '.repeat(level)
    return data.split('\n').map(line => prefix + (line.startsWith('>') ? '' : ' ') + line).join('\n')
  }

  return (messagePart.parts || []).map(p => getNestedHistory(p, level + 1)).filter(p => p).join('\n')
}

const findHeader = (headers: MessagePartHeader[], name: string) => {
  if (!headers || !Array.isArray(headers) || !name) return null;
  return headers.find(h => h?.name?.toLowerCase() === name.toLowerCase())?.value
}

const getQuotedContent = (thread: Thread) => {
  if (!thread.messages.length) return ''

  const lastMessage = thread.messages[thread.messages.length - 1]
  if (!lastMessage?.payload) return ''

  const fromHeader = findHeader(lastMessage.payload.headers, 'from')
  const dateHeader = findHeader(lastMessage.payload.headers, 'date')

  let quotedContent = []
  
  if (fromHeader && dateHeader) {
    quotedContent.push('')
    quotedContent.push(`On ${dateHeader} ${fromHeader} wrote:`)
    quotedContent.push('')
  }

  const nestedHistory = getNestedHistory(lastMessage.payload)
  if (nestedHistory) {
    quotedContent.push(nestedHistory)
    quotedContent.push('') // Add extra newline for spacing between quotes
  }

  return quotedContent.join('\n')
}

const getThreadHeaders = (thread: Thread) => {
  let headers: string[] = []

  if (!thread.messages.length) return headers

  const lastMessage = thread.messages[thread.messages.length - 1]
  const references: string[] = []
  
  let subjectHeader = findHeader(lastMessage.payload.headers, 'subject')
  if (subjectHeader) {
    if (!subjectHeader.toLowerCase().startsWith('re:')) {
      subjectHeader = `Re: ${subjectHeader}`
    }
    headers.push(`Subject: ${subjectHeader}`)
  }

  const messageIdHeader = findHeader(lastMessage.payload.headers, 'message-id')
  if (messageIdHeader) {
    headers.push(`In-Reply-To: ${messageIdHeader}`)
    references.push(messageIdHeader)
  }

  const referencesHeader = findHeader(lastMessage.payload.headers, 'references')
  if (referencesHeader) references.unshift(...referencesHeader.split(' '))

  if (references.length > 0) headers.push(`References: ${references.join(' ')}`)

  return headers
}

const constructRawMessage = async (params: NewMessage) => {
  logger('debug', 'Constructing raw email message', { params })

  let thread: Thread | null = null
  if (params.threadId) {
    thread = await callEndpoint(
      `/users/me/threads/${params.threadId}`,
      { format: 'full' }
    )
  }

  const message = []
  if (params.to) message.push(`To: ${params.to}`)
  if (params.cc) message.push(`Cc: ${params.cc}`)
  if (params.bcc) message.push(`Bcc: ${params.bcc}`)
  if (thread) message.push(...getThreadHeaders(thread))
  message.push('Content-Type: text/plain charset="UTF-8"')
  message.push('MIME-Version: 1.0')
  message.push('')
  if (params.body) message.push(params.body)
  if (thread) message.push(getQuotedContent(thread))

  logger('debug', 'Constructed raw email message', { message })

  return Buffer.from(message.join('\r\n')).toString('base64url')
}

server.tool("create_draft",
  "Create a draft email in Gmail",
  {
    raw: z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format"),
    threadId: z.string().optional().describe("The thread ID to associate this draft with"),
    to: z.string().optional().describe("The recipient's email address"),
    cc: z.string().optional().describe("The CC recipient's email address"),
    bcc: z.string().optional().describe("The BCC recipient's email address"),
    subject: z.string().optional().describe("The subject of the email"),
    body: z.string().optional().describe("The body of the email"),
    attachments: z.array(z.object({
      filename: z.string(),
      data: z.string(),
      mimeType: z.string()
    })).optional().describe("Array of attachments"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
  },
  async (params) => {
    return handleTool(async () => {
      let raw = params.raw
      if (!raw) raw = await constructRawMessage(params)

      const requestBody = { message: { raw } }
      if (params.threadId) requestBody.message.threadId = params.threadId

      const data = await callEndpoint(
        '/users/me/drafts',
        {},
        'POST',
        { requestBody }
      )

      if (data.message?.payload) {
        data.message.payload = processMessage(
          data.message.payload,
          '0',
          params.headersList,
          params.includeBodyHtml
        )
      }

      return formatResponse(data)
    })
  }
)

server.tool("send_message",
  "Send an email message to specified recipients",
  {
    raw: z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format"),
    threadId: z.string().optional().describe("The thread ID to associate this message with"),
    to: z.string().optional().describe("The recipient's email address"),
    cc: z.string().optional().describe("The CC recipient's email address"),
    bcc: z.string().optional().describe("The BCC recipient's email address"),
    subject: z.string().optional().describe("The subject of the email"),
    body: z.string().optional().describe("The body of the email"),
    attachments: z.array(z.object({
      filename: z.string(),
      data: z.string(),
      mimeType: z.string()
    })).optional().describe("Array of attachments"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
  },
  async (params) => {
    return handleTool(async () => {
      let raw = params.raw
      if (!raw) raw = await constructRawMessage(params)

      const requestBody = { raw }
      if (params.threadId) requestBody.threadId = params.threadId

      const data = await callEndpoint(
        '/users/me/messages/send',
        {},
        'POST',
        { requestBody }
      )

      if (data.payload) {
        data.payload = processMessage(
          data.payload,
          '0',
          params.headersList,
          params.includeBodyHtml
        )
      }

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
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return")
  },
  async (params) => {
    return handleTool(async () => {
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
            message.payload = processMessage(message.payload, '0', params.headersList, params.includeBodyHtml)
          }
          return message
        })
      }

      return formatResponse(data)
    })
  }
)

server.tool("get_message",
  "Get a specific message by ID with format options",
  {
    id: z.string().describe("The ID of the message to retrieve"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
  },
  async (params) => {
    return handleTool(async () => {
      let data = await callEndpoint(
        `/users/me/messages/${params.id}`,
        { format: 'full' }
      )

      if (data.payload) {
        data.payload = processMessage(data.payload, '0', params.headersList, params.includeBodyHtml)
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    includeSpamTrash: z.boolean().optional().describe("Include threads from SPAM and TRASH in the results"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return")
  },
  async (params) => {
    return handleTool(async () => {
      const data = await callEndpoint(
        '/users/me/threads',
        {
          ...params,
          format: 'full'
        }
      )

      if (data.threads) {
        data.threads = data.threads.map(thread => {
          if (thread.messages) {
            thread.messages = thread.messages.map(message => {
              if (message.payload) {
                message.payload = processMessage(
                  message.payload,
                  '0',
                  params.headersList,
                  params.includeBodyHtml
                )
              }
              return message
            })
          }
          return thread
        })
      }

      return formatResponse(data)
    })
  }
)

server.tool("get_thread",
  "Get a specific thread by ID",
  {
    id: z.string().describe("The ID of the thread to retrieve"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
  },
  async (params) => {
    return handleTool(async () => {
      let data = await callEndpoint(
        `/users/me/threads/${params.id}`,
        { format: 'full' }
      )

      if (data.messages) {
        data.messages = data.messages.map(message => {
          if (message.payload) {
            message.payload = processMessage(message.payload, '0', params.headersList, params.includeBodyHtml)
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    includeSpamTrash: z.boolean().optional().describe("Include drafts from SPAM and TRASH in the results"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return")
  },
  async (params) => {
    return handleTool(async () => {
      const data = await callEndpoint(
        '/users/me/drafts',
        { ...params, format: 'full' }
      )

      if (data.drafts) {
        data.drafts = data.drafts.map(draft => {
          if (draft.message?.payload) {
            draft.message.payload = processMessage(
              draft.message.payload,
              '0',
              params.headersList,
              params.includeBodyHtml
            )
          }
          return draft
        })
      }

      return formatResponse(data)
    })
  }
)

server.tool("get_draft",
  "Get a specific draft by ID",
  {
    id: z.string().describe("The ID of the draft to retrieve"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
  },
  async (params) => {
    return handleTool(async () => {
      const data = await callEndpoint(
        `/users/me/drafts/${params.id}`,
        { format: 'full' }
      )

      if (data.message?.payload) {
        data.message.payload = processMessage(
          data.message.payload,
          '0',
          params.headersList,
          params.includeBodyHtml
        )
      }

      return formatResponse(data)
    })
  }
)

server.tool("update_draft",
  "Replace a draft's content",
  {
    id: z.string().describe("The ID of the draft to update"),
    raw: z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format"),
    threadId: z.string().optional().describe("The thread ID to associate this draft with"),
    to: z.string().optional().describe("The recipient's email address"),
    cc: z.string().optional().describe("The CC recipient's email address"),
    bcc: z.string().optional().describe("The BCC recipient's email address"),
    subject: z.string().optional().describe("The subject of the email"),
    body: z.string().optional().describe("The body of the email"),
    attachments: z.array(z.object({
      filename: z.string(),
      data: z.string(),
      mimeType: z.string()
    })).optional().describe("Array of attachments"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
  },
  async (params) => {
    return handleTool(async () => {
      let raw = params.raw
      if (!raw) raw = await constructRawMessage(params)

      const requestBody = { message: { raw } }
      if (params.threadId) requestBody.message.threadId = params.threadId

      const data = await callEndpoint(
        `/users/me/drafts/${params.id}`,
        {},
        'PUT',
        { requestBody }
      )

      if (data.message?.payload) {
        data.message.payload = processMessage(
          data.message.payload,
          '0',
          params.headersList,
          params.includeBodyHtml
        )
      }

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
    return handleTool(async () => {
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
    return handleTool(async () => {
      const data = await callEndpoint(
        '/users/me/drafts/send',
        {},
        'POST',
        { id: params.id } // TODO fix this
      )
      return formatResponse(data)
    })
  }
)

server.tool("get_auto_forwarding",
  "Get the auto-forwarding setting for the account",
  {},
  async () => {
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    historyTypes: z.array(z.enum(['messageAdded', 'messageDeleted', 'labelAdded', 'labelRemoved'])).optional().describe("History types to be returned by the function"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return")
  },
  async (params) => {
    return handleTool(async () => {
      const data = await callEndpoint(
        '/users/me/history',
        {
          ...params,
          historyTypes: params.historyTypes?.join(','),
          format: 'full'
        }
      )

      // Process messages in history records
      if (data.history) {
        data.history = data.history.map(record => {
          ['messages', 'messagesAdded', 'messagesDeleted'].forEach(field => {
            if (record[field]) {
              record[field] = record[field].map(message => {
                if (message.message?.payload) {
                  message.message.payload = processMessage(
                    message.message.payload,
                    '0',
                    params.headersList,
                    params.includeBodyHtml
                  )
                }
                return message
              })
            }
          })
          return record
        })
      }

      return formatResponse(data)
    })
  }
)

server.tool("get_profile",
  "Get the current user's Gmail profile",
  {},
  async () => {
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    return handleTool(async () => {
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
    deleted: z.boolean().optional().describe("Mark the email as permanently deleted"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
  },
  async (params) => {
    return handleTool(async () => {
      const data = await callEndpoint(
        '/users/me/messages/import',
        {},
        'POST',
        {
          raw: params.raw,
          internalDateSource: params.internalDateSource,
          neverMarkSpam: params.neverMarkSpam,
          processForCalendar: params.processForCalendar,
          deleted: params.deleted
        }
      )

      if (data.payload) {
        data.payload = processMessage(
          data.payload,
          '0',
          params.headersList,
          params.includeBodyHtml
        )
      }

      return formatResponse(data)
    })
  }
)

server.tool("insert_message",
  "Insert a message into the mailbox",
  {
    raw: z.string().describe("The entire email message in base64url encoded RFC 2822 format"),
    internalDateSource: z.enum(['dateHeader', 'receivedTime']).optional().describe("Source for the message's internal date"),
    deleted: z.boolean().optional().describe("Mark the email as permanently deleted"),
    headersList: z.array(z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
  },
  async (params) => {
    return handleTool(async () => {
      const data = await callEndpoint(
        '/users/me/messages',
        {},
        'POST',
        {
          raw: params.raw,
          internalDateSource: params.internalDateSource,
          deleted: params.deleted
        }
      )

      if (data.payload) {
        data.payload = processMessage(
          data.payload,
          '0',
          params.headersList,
          params.includeBodyHtml
        )
      }

      return formatResponse(data)
    })
  }
)
const transport = new StdioServerTransport()
await server.connect(transport)
