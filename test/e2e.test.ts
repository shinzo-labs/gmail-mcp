import { StdioClientTransport, StdioServerParameters } from '@modelcontextprotocol/sdk/client/stdio.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js'
import path from 'path'

const RESPONSE_TIMEOUT = 1_000 // 1s
const START_DELAY = 1_000 // 1s
const TEST_TIMEOUT = 10_000 // 10s

const TOTAL_TOOLS = 64

const streamableClientUrl = new URL(`http://localhost:${process.env.PORT || 3000}/mcp`)

jest.setTimeout(TEST_TIMEOUT)

type ReadMessageType = {
  jsonrpc: string
  id: number
  result: {
    content?: {
      type: string
      text: string
    }[],
    tools?: any[]
  }
}

// In some tests the argument IDs in this object are modified, ensure the ID is always set per-test where relevant
const jsonRpcMessage: Record<string, JSONRPCMessage> = {
  ping: { jsonrpc: "2.0", id: 1, method: "ping" },
  pong: { jsonrpc: '2.0', id: 1, result: {} },
  initialize: {
    jsonrpc: "2.0", id: 1, method: "initialize", params: {
      clientInfo: { name: "test-client", version: "1.0" },
      protocolVersion: "2025-05-13",
      capabilities: {},
    }
  },
  toolsList: { jsonrpc: "2.0", id: 1, method: "tools/list" },
  getProfile: {
    jsonrpc: "2.0", id: 1, method: "tools/call", params: {
      name: "get_profile"
    }
  },
  createDraft: {
    jsonrpc: "2.0", id: 1, method: "tools/call", params: {
      name: "create_draft",
      arguments: {
        subject: "Test Subject",
        body: "Test Body",
        to: ["test@example.com"],
        cc: ["test@example.com"],
        bcc: ["test@example.com"]
      }
    }
  },
  listDrafts: {
    jsonrpc: "2.0", id: 1, method: "tools/call", params: {
      name: "list_drafts",
      arguments: { }
    }
  },
  getDraft: {
    jsonrpc: "2.0", id: 1, method: "tools/call", params: {
      name: "get_draft",
      arguments: {
        id: "test-id"
      }
    }
  },
  updateDraft: {
    jsonrpc: "2.0", id: 1, method: "tools/call", params: {
      name: "update_draft",
      arguments: {
        id: "test-id",
        subject: "Updated Subject",
        body: "Updated Body",
        to: ["updated@example.com"],
        cc: ["updated@example.com"],
        bcc: ["updated@example.com"]
      }
    }
  },
  deleteDraft: {
    jsonrpc: "2.0", id: 1, method: "tools/call", params: {
      name: "delete_draft",
      arguments: {
        id: "test-id"
      }
    }
  }
}

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

const sendPostRequest = async (message: JSONRPCMessage | JSONRPCMessage[], sessionId?: string) => (
  fetch(streamableClientUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...(sessionId ? { "mcp-session-id": sessionId } : {}),
    },
    body: JSON.stringify(message),
  })
)

const getSSEData = async (response: Response) => {
  const reader = response.body?.getReader()
  const { value } = await reader!.read()
  const text = new TextDecoder().decode(value)
  const dataLine = text.split('\n').find(line => line.startsWith('data:'))
  expect(dataLine).toBeDefined()
  return JSON.parse(dataLine!.slice(5).trim())
}

describe('Gmail MCP', () => {
  let stdioClient: StdioClientTransport
  let streamableClient: StreamableHTTPClientTransport

  beforeAll(async () => {
    const serverParameters: StdioServerParameters = {
      command: "node",
      args: [path.resolve(__dirname, '../dist/index.js')],
      env: process.env as Record<string, string>
    }

    stdioClient = new StdioClientTransport(serverParameters)
    await stdioClient.start()
    streamableClient = new StreamableHTTPClientTransport(streamableClientUrl)
  })

  afterAll(async () => {
    await stdioClient.close()
  })

  describe('Stdio Transport', () => {
    let readMessages: ReadMessageType[]
    let errors: Error[]
    let draftId: string

    beforeAll(async () => {
      await delay(START_DELAY)
      stdioClient.onmessage = (message) => readMessages.push(message as ReadMessageType)
      stdioClient.onerror = (error) => errors.push(error)
    })

    beforeEach(async () => {
      readMessages = []
      errors = []
    })

    it('responds to ping', async () => {
      stdioClient.send(jsonRpcMessage.ping)
      await delay(RESPONSE_TIMEOUT)

      expect(readMessages).toHaveLength(1)
      expect(readMessages[0]).toEqual(jsonRpcMessage.pong)
      expect(errors).toHaveLength(0)
    })

    it('returns a list of tools', async () => {
      stdioClient.send(jsonRpcMessage.toolsList)
      await delay(RESPONSE_TIMEOUT)

      expect(readMessages).toHaveLength(1)
      expect(readMessages[0].result.tools?.length).toEqual(TOTAL_TOOLS)
    })

    it('can call the get_profile tool', async () => {
      stdioClient.send(jsonRpcMessage.getProfile)
      await delay(RESPONSE_TIMEOUT)

      expect(readMessages).toHaveLength(1)
      expect(readMessages[0].result.content?.length).toEqual(1)

      const firstMessage = JSON.parse(readMessages[0].result.content?.[0].text ?? '{}')
      expect(firstMessage.emailAddress).toBeDefined()
      expect(firstMessage.messagesTotal).toBeDefined()
      expect(firstMessage.historyId).toBeDefined()
    })

    it('can call the create_draft tool', async () => {
      stdioClient.send(jsonRpcMessage.createDraft)
      await delay(RESPONSE_TIMEOUT)

      expect(readMessages).toHaveLength(1)
      expect(readMessages[0].result.content?.length).toEqual(1)

      draftId = JSON.parse(readMessages[0].result.content?.[0].text ?? '{}').id
      expect(draftId).toBeDefined()
    })

    it('can call the list_drafts tool', async () => {
      stdioClient.send(jsonRpcMessage.listDrafts)
      await delay(RESPONSE_TIMEOUT)

      expect(readMessages).toHaveLength(1)
      expect(readMessages[0].result.content?.length).toEqual(1)

      const draftsList = JSON.parse(readMessages[0].result.content?.[0].text ?? '{}')
      const createdDraft = draftsList.find((draft: any) => draft.id === draftId)
      expect(createdDraft).toBeDefined()
    })

    it('can call the get_draft tool', async () => {
      jsonRpcMessage.getDraft["params"].arguments.id = draftId // Beware this modifies the original object
      stdioClient.send(jsonRpcMessage.getDraft)
      await delay(RESPONSE_TIMEOUT)

      expect(readMessages).toHaveLength(1)
      expect(readMessages[0].result.content?.length).toEqual(1)

      const draftEmail = JSON.parse(readMessages[0].result.content?.[0].text ?? '{}')
      expect(draftEmail.message.labelIds).toContain("DRAFT")
      expect(draftEmail.message.snippet).toEqual("Test Body")
    })

    it('can call the delete_draft tool', async () => {
      jsonRpcMessage.deleteDraft["params"].arguments.id = draftId // Beware this modifies the original object
      stdioClient.send(jsonRpcMessage.deleteDraft)
      await delay(RESPONSE_TIMEOUT)

      expect(readMessages).toHaveLength(1)
      expect(readMessages[0].result.content?.length).toEqual(1)
    })
  })

  describe('Streamable HTTP Transport', () => {
    let draftId: string

    it('responds to ping', async () => {
      const response = await sendPostRequest(jsonRpcMessage.ping)
      expect(response.status).toBe(200)

      const sseResponse = await getSSEData(response)
      expect(sseResponse).toEqual(jsonRpcMessage.pong)
    })

    it('returns a list of tools', async () => {
      const response = await sendPostRequest(jsonRpcMessage.toolsList)
      expect(response.status).toBe(200)

      const sseResponse = await getSSEData(response)
      expect(sseResponse.result.tools?.length).toEqual(TOTAL_TOOLS)
    })

    it('can call the get_profile tool', async () => {
      const response = await sendPostRequest(jsonRpcMessage.getProfile)
      expect(response.status).toBe(200)

      const sseResponse = await getSSEData(response)
      expect(sseResponse.result.content?.length).toEqual(1)

      const firstMessage = JSON.parse(sseResponse.result.content?.[0].text ?? '{}')
      expect(firstMessage.emailAddress).toBeDefined()
      expect(firstMessage.messagesTotal).toBeDefined()
      expect(firstMessage.historyId).toBeDefined()
    })

    it('can call the create_draft tool', async () => {
      const response = await sendPostRequest(jsonRpcMessage.createDraft)
      expect(response.status).toBe(200)

      const sseResponse = await getSSEData(response)
      expect(sseResponse.result.content?.length).toEqual(1)

      draftId = JSON.parse(sseResponse.result.content?.[0].text).id
      expect(draftId).toBeDefined()
    })

    it('can call the list_drafts tool', async () => {
      const response = await sendPostRequest(jsonRpcMessage.listDrafts)
      expect(response.status).toBe(200)

      const sseResponse = await getSSEData(response)
      expect(sseResponse.result.content?.length).toEqual(1)

      const draftsList = JSON.parse(sseResponse.result.content?.[0].text)
      const createdDraft = draftsList.find((draft: any) => draft.id === draftId)
      expect(createdDraft).toBeDefined()
    })

    it('can call the get_draft tool', async () => {
      jsonRpcMessage.getDraft["params"].arguments.id = draftId // Beware this modifies the original object
      const response = await sendPostRequest(jsonRpcMessage.getDraft)
      expect(response.status).toBe(200)

      const getDraftSseResponse = await getSSEData(response)
      expect(getDraftSseResponse.result.content?.length).toEqual(1)

      const draftEmail = JSON.parse(getDraftSseResponse.result.content?.[0].text)
      expect(draftEmail.message.labelIds).toContain("DRAFT")
      expect(draftEmail.message.snippet).toEqual("Test Body")
    })

    // it('can call the update_draft tool', async () => {
    //   jsonRpcMessage.updateDraft["params"].arguments.id = draftId // Beware this modifies the original object
    //   const response = await sendPostRequest(jsonRpcMessage.updateDraft)
    //   expect(response.status).toBe(200)

    //   const updateDraftSseResponse = await getSSEData(response)
    //   expect(updateDraftSseResponse.result.content?.length).toEqual(1)

    //   const updatedDraft = JSON.parse(updateDraftSseResponse.result.content?.[0].text)
    //   console.log(updatedDraft)
    //   expect(updatedDraft.message.labelIds).toContain("DRAFT")
    //   // expect(updatedDraft.message.snippet).toEqual("Updated Body") // TODO this test fails, update before uncommenting the update_draft method
    // })

    it('can call the delete_draft tool', async () => {
      jsonRpcMessage.deleteDraft["params"].arguments.id = draftId // Beware this modifies the original object
      const response = await sendPostRequest(jsonRpcMessage.deleteDraft)
      expect(response.status).toBe(200)

      const deleteDraftSseResponse = await getSSEData(response)
      expect(deleteDraftSseResponse.result.content?.length).toEqual(1)
    })
  })
})
