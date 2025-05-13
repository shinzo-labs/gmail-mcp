import { StdioClientTransport, StdioServerParameters } from '@modelcontextprotocol/sdk/client/stdio.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js'
import path from 'path'

const RESPONSE_TIMEOUT = 1_000 // 1s
const START_DELAY = 1_000 // 1s
const TEST_TIMEOUT = 10_000 // 10s

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

const jsonRpcMessage: Record<string, JSONRPCMessage> = {
  ping: { jsonrpc: "2.0", id: 1, method: "ping" },
  pong: { jsonrpc: '2.0', id: 1, result: { } },
  initialize: {
    jsonrpc: "2.0", id: 2, method: "initialize", params: {
      clientInfo: { name: "test-client", version: "1.0" },
      protocolVersion: "2025-05-13",
      capabilities: { },
    }
  },
  toolsList: { jsonrpc: "2.0", id: 3, method: "tools/list" },
  getProfile: { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "get_profile" } },
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
      expect(readMessages[0].result.tools?.length).toEqual(65)
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
  })

  describe('Streamable HTTP Transport', () => {
    let sessionId: string

    beforeAll(async () => {
      // const response = await sendPostRequest(jsonRpcMessage.initialize)
      // expect(response.status).toBe(200)

      // const extractedSessionId = response.headers.get("mcp-session-id")
      // expect(extractedSessionId).toBeDefined()
      // sessionId = extractedSessionId as string
    })

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
      expect(sseResponse.result.tools?.length).toEqual(65)
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
  })
})
