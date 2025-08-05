#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { createStatefulServer } from "@smithery/sdk/server/stateful.js"
import { z } from "zod"
import { google, gmail_v1 } from 'googleapis'
import fs from "fs"
import { createOAuth2Client, launchAuthServer, validateCredentials } from "./oauth2.js"
import { MCP_CONFIG_DIR, PORT, TELEMETRY_ENABLED } from "./config.js"
import { instrumentServer } from "@shinzolabs/instrumentation-mcp"

type Draft = gmail_v1.Schema$Draft
type DraftCreateParams = gmail_v1.Params$Resource$Users$Drafts$Create
type DraftUpdateParams = gmail_v1.Params$Resource$Users$Drafts$Update
type Message = gmail_v1.Schema$Message
type MessagePart = gmail_v1.Schema$MessagePart
type MessagePartBody = gmail_v1.Schema$MessagePartBody
type MessagePartHeader = gmail_v1.Schema$MessagePartHeader
type MessageSendParams = gmail_v1.Params$Resource$Users$Messages$Send
type Thread = gmail_v1.Schema$Thread

type NewMessage = {
  threadId?: string
  raw?: string
  to?: string[] | undefined
  cc?: string[] | undefined
  bcc?: string[] | undefined
  subject?: string | undefined
  body?: string | undefined
  includeBodyHtml?: boolean
}

const RESPONSE_HEADERS_LIST = [
  'Date',
  'From',
  'To',
  'Subject',
  'Message-ID',
  'In-Reply-To',
  'References'
]

const defaultOAuth2Client = createOAuth2Client()

const defaultGmailClient = defaultOAuth2Client ? google.gmail({ version: 'v1', auth: defaultOAuth2Client }) : null

const formatResponse = (response: any) => ({ content: [{ type: "text", text: JSON.stringify(response) }] })

const handleTool = async (queryConfig: Record<string, any> | undefined, apiCall: (gmail: gmail_v1.Gmail) => Promise<any>) => {
  try {
    const oauth2Client = queryConfig ? createOAuth2Client(queryConfig) : defaultOAuth2Client
    if (!oauth2Client) throw new Error('OAuth2 client could not be created, please check your credentials')

    const credentialsAreValid = await validateCredentials(oauth2Client)
    if (!credentialsAreValid) throw new Error('OAuth2 credentials are invalid, please re-authenticate')

    const gmailClient = queryConfig ? google.gmail({ version: 'v1', auth: oauth2Client }) : defaultGmailClient
    if (!gmailClient) throw new Error('Gmail client could not be created, please check your credentials')

    const result = await apiCall(gmailClient)
    return result
  } catch (error: any) {
    // Check for specific authentication errors
    if (
      error.message?.includes("invalid_grant") ||
      error.message?.includes("refresh_token") ||
      error.message?.includes("invalid_client") ||
      error.message?.includes("unauthorized_client") ||
      error.code === 401 ||
      error.code === 403
    ) {
      return formatResponse({
        error: `Authentication failed: ${error.message}. Please re-authenticate by running: npx @shinzolabs/gmail-mcp auth`,
      });
    }

    return formatResponse({ error: `Tool execution failed: ${error.message}` });
  }
}

const decodedBody = (body: MessagePartBody) => {
  if (!body?.data) return body

  const decodedData = Buffer.from(body.data, 'base64').toString('utf-8')
  const decodedBody: MessagePartBody = {
    data: decodedData,
    size: body.data.length,
    attachmentId: body.attachmentId
  }
  return decodedBody
}

const processMessagePart = (messagePart: MessagePart, includeBodyHtml = false): MessagePart => {
  if ((messagePart.mimeType !== 'text/html' || includeBodyHtml) && messagePart.body) {
    messagePart.body = decodedBody(messagePart.body)
  }

  if (messagePart.parts) {
    messagePart.parts = messagePart.parts.map(part => processMessagePart(part, includeBodyHtml))
  }

  if (messagePart.headers) {
    messagePart.headers = messagePart.headers.filter(header => RESPONSE_HEADERS_LIST.includes(header.name || ''))
  }

  return messagePart
}

const getNestedHistory = (messagePart: MessagePart, level = 1): string => {
  if (messagePart.mimeType === 'text/plain' && messagePart.body?.data) {
    const { data } = decodedBody(messagePart.body)
    if (!data) return ''
    return data.split('\n').map(line => '>' + (line.startsWith('>') ? '' : ' ') + line).join('\n')
  }

  return (messagePart.parts || []).map(p => getNestedHistory(p, level + 1)).filter(p => p).join('\n')
}

const findHeader = (headers: MessagePartHeader[] | undefined, name: string) => {
  if (!headers || !Array.isArray(headers) || !name) return undefined
  return headers.find(h => h?.name?.toLowerCase() === name.toLowerCase())?.value ?? undefined
}

const formatEmailList = (emailList: string | null | undefined) => {
  if (!emailList) return []
  return emailList.split(',').map(email => email.trim())
}

const getQuotedContent = (thread: Thread) => {
  if (!thread.messages?.length) return ''

  const sentMessages = thread.messages.filter(msg =>
    msg.labelIds?.includes('SENT') ||
    (!msg.labelIds?.includes('DRAFT') && findHeader(msg.payload?.headers || [], 'date'))
  )

  if (!sentMessages.length) return ''

  const lastMessage = sentMessages[sentMessages.length - 1]
  if (!lastMessage?.payload) return ''

  let quotedContent = []

  if (lastMessage.payload.headers) {
    const fromHeader = findHeader(lastMessage.payload.headers || [], 'from')
    const dateHeader = findHeader(lastMessage.payload.headers || [], 'date')
    if (fromHeader && dateHeader) {
      quotedContent.push('')
      quotedContent.push(`On ${dateHeader} ${fromHeader} wrote:`)
      quotedContent.push('')
    }
  }

  const nestedHistory = getNestedHistory(lastMessage.payload)
  if (nestedHistory) {
    quotedContent.push(nestedHistory)
    quotedContent.push('')
  }

  return quotedContent.join('\n')
}

const getThreadHeaders = (thread: Thread) => {
  let headers: string[] = []

  if (!thread.messages?.length) return headers

  const lastMessage = thread.messages[thread.messages.length - 1]
  const references: string[] = []

  let subjectHeader = findHeader(lastMessage.payload?.headers || [], 'subject')
  if (subjectHeader) {
    if (!subjectHeader.toLowerCase().startsWith('re:')) {
      subjectHeader = `Re: ${subjectHeader}`
    }
    headers.push(`Subject: ${subjectHeader}`)
  }

  const messageIdHeader = findHeader(lastMessage.payload?.headers || [], 'message-id')
  if (messageIdHeader) {
    headers.push(`In-Reply-To: ${messageIdHeader}`)
    references.push(messageIdHeader)
  }

  const referencesHeader = findHeader(lastMessage.payload?.headers || [], 'references')
  if (referencesHeader) references.unshift(...referencesHeader.split(' '))

  if (references.length > 0) headers.push(`References: ${references.join(' ')}`)

  return headers
}

const wrapTextBody = (text: string): string => text.split('\n').map(line => {
  if (line.length <= 76) return line
  const chunks = line.match(/.{1,76}/g) || []
  return chunks.join('=\n')
}).join('\n')

const constructRawMessage = async (gmail: gmail_v1.Gmail, params: NewMessage) => {
  let thread: Thread | null = null
  if (params.threadId) {
    const threadParams = { userId: 'me', id: params.threadId, format: 'full' }
    const { data } = await gmail.users.threads.get(threadParams)
    thread = data
  }

  const message = []
  if (params.to?.length) message.push(`To: ${wrapTextBody(params.to.join(', '))}`)
  if (params.cc?.length) message.push(`Cc: ${wrapTextBody(params.cc.join(', '))}`)
  if (params.bcc?.length) message.push(`Bcc: ${wrapTextBody(params.bcc.join(', '))}`)
  if (thread) {
    message.push(...getThreadHeaders(thread).map(header => wrapTextBody(header)))
  } else if (params.subject) {
    message.push(`Subject: ${wrapTextBody(params.subject)}`)
  } else {
    message.push('Subject: (No Subject)')
  }
  message.push('Content-Type: text/plain; charset="UTF-8"')
  message.push('Content-Transfer-Encoding: quoted-printable')
  message.push('MIME-Version: 1.0')
  message.push('')

  if (params.body) message.push(wrapTextBody(params.body))

  if (thread) {
    const quotedContent = getQuotedContent(thread)
    if (quotedContent) {
      message.push('')
      message.push(wrapTextBody(quotedContent))
    }
  }

  return Buffer.from(message.join('\r\n')).toString('base64url').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function getConfig(config: any) {
  return {
    telemetryEnabled: config?.TELEMETRY_ENABLED || TELEMETRY_ENABLED
  }
}

function createServer({ config }: { config?: Record<string, any> }) {
  const serverInfo = {
    name: "Gmail-MCP",
    version: "1.7.4",
    description: "Gmail MCP - Provides complete Gmail API access with file-based OAuth2 authentication"
  }

  const server = new McpServer(serverInfo)

  const { telemetryEnabled } = getConfig(config)

  if (telemetryEnabled !== "false") {
    const telemetry = instrumentServer(server, {
      serverName: serverInfo.name,
      serverVersion: serverInfo.version,
      exporterEndpoint: "https://api.otel.shinzo.tech/v1"
    })
  }

  server.tool("create_draft",
    "Create a draft email in Gmail. Note the mechanics of the raw parameter.",
    {
      raw: z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format, ignores params.to, cc, bcc, subject, body, includeBodyHtml if provided"),
      threadId: z.string().optional().describe("The thread ID to associate this draft with"),
      to: z.array(z.string()).optional().describe("List of recipient email addresses"),
      cc: z.array(z.string()).optional().describe("List of CC recipient email addresses"),
      bcc: z.array(z.string()).optional().describe("List of BCC recipient email addresses"),
      subject: z.string().optional().describe("The subject of the email"),
      body: z.string().optional().describe("The body of the email"),
      includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return for each body, excluded by default because they can be excessively large")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        let raw = params.raw
        if (!raw) raw = await constructRawMessage(gmail, params)

        const draftCreateParams: DraftCreateParams = { userId: 'me', requestBody: { message: { raw } } }
        if (params.threadId && draftCreateParams.requestBody?.message) {
          draftCreateParams.requestBody.message.threadId = params.threadId
        }

        const { data } = await gmail.users.drafts.create(draftCreateParams)

        if (data.message?.payload) {
          data.message.payload = processMessagePart(
            data.message.payload,
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.drafts.delete({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_draft",
    "Get a specific draft by ID",
    {
      id: z.string().describe("The ID of the draft to retrieve"),
      includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return for each body, excluded by default because they can be excessively large")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.drafts.get({ userId: 'me', id: params.id, format: 'full' })

        if (data.message?.payload) {
          data.message.payload = processMessagePart(
            data.message.payload,
            params.includeBodyHtml
          )
        }

        return formatResponse(data)
      })
    }
  )

  server.tool("list_drafts",
    "List drafts in the user's mailbox",
    {
      maxResults: z.number().optional().describe("Maximum number of drafts to return. Accepts values between 1-500"),
      q: z.string().optional().describe("Only return drafts matching the specified query. Supports the same query format as the Gmail search box"),
      includeSpamTrash: z.boolean().optional().describe("Include drafts from SPAM and TRASH in the results"),
      includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return for each body, excluded by default because they can be excessively large"),
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        let drafts: Draft[] = []

        const { data } = await gmail.users.drafts.list({ userId: 'me', ...params })

        drafts.push(...data.drafts || [])

        while (data.nextPageToken) {
          const { data: nextData } = await gmail.users.drafts.list({ userId: 'me', ...params, pageToken: data.nextPageToken })
          drafts.push(...nextData.drafts || [])
        }

        if (drafts) {
          drafts = drafts.map(draft => {
            if (draft.message?.payload) {
              draft.message.payload = processMessagePart(
                draft.message.payload,
                params.includeBodyHtml
              )
            }
            return draft
          })
        }

        return formatResponse(drafts)
      })
    }
  )

  server.tool("send_draft",
    "Send an existing draft",
    {
      id: z.string().describe("The ID of the draft to send")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        try {
          const { data } = await gmail.users.drafts.send({ userId: 'me', requestBody: { id: params.id } })
          return formatResponse(data)
        } catch (error) {
          return formatResponse({ error: 'Error sending draft, are you sure you have at least one recipient?' })
        }
      })
    }
  )

  // TODO debug issue with subject not being applied correctly
  // server.tool("update_draft",
  //   "Replace a draft's content. Note the mechanics of the threadId and raw parameters.",
  //   {
  //     id: z.string().describe("The ID of the draft to update"),
  //     threadId: z.string().optional().describe("The thread ID to associate this draft with, will be copied from the current draft if not provided"),
  //     raw: z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format, ignores params.to, cc, bcc, subject, body, includeBodyHtml if provided"),
  //     to: z.array(z.string()).optional().describe("List of recipient email addresses, will be copied from the current draft if not provided"),
  //     cc: z.array(z.string()).optional().describe("List of CC recipient email addresses, will be copied from the current draft if not provided"),
  //     bcc: z.array(z.string()).optional().describe("List of BCC recipient email addresses, will be copied from the current draft if not provided"),
  //     subject: z.string().optional().describe("The subject of the email, will be copied from the current draft if not provided"),
  //     body: z.string().optional().describe("The body of the email, will be copied from the current draft if not provided"),
  //     includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return for each body, excluded by default because they can be excessively large")
  //   },
  //   async (params) => {
  //     return handleTool(config, async (gmail: gmail_v1.Gmail) => {
  //       let raw = params.raw
  //       const currentDraft = await gmail.users.drafts.get({ userId: 'me', id: params.id, format: 'full' })
  //       const { payload } = currentDraft.data.message ?? {}

  //       if (currentDraft.data.message?.threadId && !params.threadId) params.threadId = currentDraft.data.message.threadId
  //       if (!params.to) params.to = formatEmailList(findHeader(payload?.headers || [], 'to'))
  //       if (!params.cc) params.cc = formatEmailList(findHeader(payload?.headers || [], 'cc'))
  //       if (!params.bcc) params.bcc = formatEmailList(findHeader(payload?.headers || [], 'bcc'))
  //       if (!params.subject) params.subject = findHeader(payload?.headers || [], 'subject')
  //       if (!params.body) params.body = payload?.parts?.find(p => p.mimeType === 'text/plain')?.body?.data ?? undefined

  //       if (!raw) raw = await constructRawMessage(gmail, params)

  //       const draftUpdateParams: DraftUpdateParams = { userId: 'me', id: params.id, requestBody: { message: { raw, id: params.id } } }
  //       if (params.threadId && draftUpdateParams.requestBody?.message) {
  //         draftUpdateParams.requestBody.message.threadId = params.threadId
  //       }

  //       const { data } = await gmail.users.drafts.update(draftUpdateParams)

  //       if (data.message?.payload) {
  //         data.message.payload = processMessagePart(
  //           data.message.payload,
  //           params.includeBodyHtml
  //         )
  //       }

  //       return formatResponse(data)
  //     })
  //   }
  // )

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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.create({ userId: 'me', requestBody: params })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.delete({ userId: 'me', id: params.id })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.get({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("list_labels",
    "List all labels in the user's mailbox",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.list({ userId: 'me' })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.patch({ userId: 'me', id, requestBody: labelData })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.update({ userId: 'me', id, requestBody: labelData })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.batchDelete({ userId: 'me', requestBody: { ids: params.ids } })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.batchModify({ userId: 'me', requestBody: { ids: params.ids, addLabelIds: params.addLabelIds, removeLabelIds: params.removeLabelIds } })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.delete({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_message",
    "Get a specific message by ID with format options",
    {
      id: z.string().describe("The ID of the message to retrieve"),
      includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return for each body, excluded by default because they can be excessively large")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.get({ userId: 'me', id: params.id, format: 'full' })

        if (data.payload) {
          data.payload = processMessagePart(data.payload, params.includeBodyHtml)
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
      includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return for each body, excluded by default because they can be excessively large"),
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.list({ userId: 'me', ...params })

        if (data.messages) {
          data.messages = data.messages.map((message: Message) => {
            if (message.payload) {
              message.payload = processMessagePart(
                message.payload,
                params.includeBodyHtml
              )
            }
            return message
          })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.modify({ userId: 'me', id: params.id, requestBody: { addLabelIds: params.addLabelIds, removeLabelIds: params.removeLabelIds } })
        return formatResponse(data)
      })
    }
  )

  server.tool("send_message",
    "Send an email message to specified recipients. Note the mechanics of the raw parameter.",
    {
      raw: z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format, ignores params.to, cc, bcc, subject, body, includeBodyHtml if provided"),
      threadId: z.string().optional().describe("The thread ID to associate this message with"),
      to: z.array(z.string()).optional().describe("List of recipient email addresses"),
      cc: z.array(z.string()).optional().describe("List of CC recipient email addresses"),
      bcc: z.array(z.string()).optional().describe("List of BCC recipient email addresses"),
      subject: z.string().optional().describe("The subject of the email"),
      body: z.string().optional().describe("The body of the email"),
      includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return for each body, excluded by default because they can be excessively large")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        let raw = params.raw
        if (!raw) raw = await constructRawMessage(gmail, params)

        const messageSendParams: MessageSendParams = { userId: 'me', requestBody: { raw } }
        if (params.threadId && messageSendParams.requestBody) {
          messageSendParams.requestBody.threadId = params.threadId
        }

        const { data } = await gmail.users.messages.send(messageSendParams)

        if (data.payload) {
          data.payload = processMessagePart(
            data.payload,
            params.includeBodyHtml
          )
        }

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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.trash({ userId: 'me', id: params.id })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.untrash({ userId: 'me', id: params.id })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.attachments.get({ userId: 'me', messageId: params.messageId, id: params.id })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.delete({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_thread",
    "Get a specific thread by ID",
    {
      id: z.string().describe("The ID of the thread to retrieve"),
      includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return for each body, excluded by default because they can be excessively large")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.get({ userId: 'me', id: params.id, format: 'full' })

        if (data.messages) {
          data.messages = data.messages.map(message => {
            if (message.payload) {
              message.payload = processMessagePart(message.payload, params.includeBodyHtml)
            }
            return message
          })
        }

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
      includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return for each body, excluded by default because they can be excessively large"),
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.list({ userId: 'me', ...params })

        if (data.threads) {
          data.threads = data.threads.map(thread => {
            if (thread.messages) {
              thread.messages = thread.messages.map(message => {
                if (message.payload) {
                  message.payload = processMessagePart(
                    message.payload,
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

  server.tool("modify_thread",
    "Modify the labels applied to a thread",
    {
      id: z.string().describe("The ID of the thread to modify"),
      addLabelIds: z.array(z.string()).optional().describe("A list of label IDs to add to the thread"),
      removeLabelIds: z.array(z.string()).optional().describe("A list of label IDs to remove from the thread")
    },
    async (params) => {
      const { id, ...threadData } = params
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.modify({ userId: 'me', id, requestBody: threadData })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.trash({ userId: 'me', id: params.id })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.untrash({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_auto_forwarding",
    "Gets auto-forwarding settings",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.getAutoForwarding({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_imap",
    "Gets IMAP settings",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.getImap({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_language",
    "Gets language settings",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.getLanguage({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_pop",
    "Gets POP settings",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.getPop({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_vacation",
    "Get vacation responder settings",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.getVacation({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("update_auto_forwarding",
    "Updates automatic forwarding settings",
    {
      enabled: z.boolean().describe("Whether all incoming mail is automatically forwarded to another address"),
      emailAddress: z.string().describe("Email address to which messages should be automatically forwarded"),
      disposition: z.enum(['leaveInInbox', 'archive', 'trash', 'markRead']).describe("The state in which messages should be left after being forwarded")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.updateAutoForwarding({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("update_imap",
    "Updates IMAP settings",
    {
      enabled: z.boolean().describe("Whether IMAP is enabled for the account"),
      expungeBehavior: z.enum(['archive', 'trash', 'deleteForever']).optional().describe("The action that will be executed on a message when it is marked as deleted and expunged from the last visible IMAP folder"),
      maxFolderSize: z.number().optional().describe("An optional limit on the number of messages that can be accessed through IMAP")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.updateImap({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("update_language",
    "Updates language settings",
    {
      displayLanguage: z.string().describe("The language to display Gmail in, formatted as an RFC 3066 Language Tag")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.updateLanguage({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("update_pop",
    "Updates POP settings",
    {
      accessWindow: z.enum(['disabled', 'allMail', 'fromNowOn']).describe("The range of messages which are accessible via POP"),
      disposition: z.enum(['archive', 'trash', 'leaveInInbox']).describe("The action that will be executed on a message after it has been fetched via POP")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.updatePop({ userId: 'me', requestBody: params })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.updateVacation({ userId: 'me', requestBody: params })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.delegates.create({ userId: 'me', requestBody: { delegateEmail: params.delegateEmail } })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.delegates.delete({ userId: 'me', delegateEmail: params.delegateEmail })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.delegates.get({ userId: 'me', delegateEmail: params.delegateEmail })
        return formatResponse(data)
      })
    }
  )

  server.tool("list_delegates",
    "Lists the delegates for the specified account",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.delegates.list({ userId: 'me' })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.filters.create({ userId: 'me', requestBody: params })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.filters.delete({ userId: 'me', id: params.id })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.filters.get({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("list_filters",
    "Lists the message filters of a Gmail user",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.filters.list({ userId: 'me' })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.forwardingAddresses.create({ userId: 'me', requestBody: params })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.forwardingAddresses.delete({ userId: 'me', forwardingEmail: params.forwardingEmail })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.forwardingAddresses.get({ userId: 'me', forwardingEmail: params.forwardingEmail })
        return formatResponse(data)
      })
    }
  )

  server.tool("list_forwarding_addresses",
    "Lists the forwarding addresses for the specified account",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.forwardingAddresses.list({ userId: 'me' })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.create({ userId: 'me', requestBody: params })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.delete({ userId: 'me', sendAsEmail: params.sendAsEmail })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.get({ userId: 'me', sendAsEmail: params.sendAsEmail })
        return formatResponse(data)
      })
    }
  )

  server.tool("list_send_as",
    "Lists the send-as aliases for the specified account",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.list({ userId: 'me' })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.patch({ userId: 'me', sendAsEmail, requestBody: patchData })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.update({ userId: 'me', sendAsEmail, requestBody: updateData })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.verify({ userId: 'me', sendAsEmail: params.sendAsEmail })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.delete({ userId: 'me', sendAsEmail: params.sendAsEmail, id: params.id })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.get({ userId: 'me', sendAsEmail: params.sendAsEmail, id: params.id })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.insert({ userId: 'me', sendAsEmail: params.sendAsEmail, requestBody: params })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.list({ userId: 'me', sendAsEmail: params.sendAsEmail })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.setDefault({ userId: 'me', sendAsEmail: params.sendAsEmail, id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_profile",
    "Get the current user's Gmail profile",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.getProfile({ userId: 'me' })
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
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.watch({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("stop_mail_watch",
    "Stop receiving push notifications for the given user mailbox",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.stop({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  return server.server
}

const main = async () => {
  fs.mkdirSync(MCP_CONFIG_DIR, { recursive: true })

  if (process.argv[2] === 'auth') {
    if (!defaultOAuth2Client) throw new Error('OAuth2 client could not be created, please check your credentials')
    await launchAuthServer(defaultOAuth2Client)
    process.exit(0)
  }

  // Stdio Server
  const stdioServer = createServer({})
  const transport = new StdioServerTransport()
  await stdioServer.connect(transport)

  // Streamable HTTP Server
  const { app } = createStatefulServer(createServer)
  app.listen(PORT)
}

main()
