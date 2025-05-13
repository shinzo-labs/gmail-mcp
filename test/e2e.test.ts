import { StdioClientTransport, StdioServerParameters } from '@modelcontextprotocol/sdk/client/stdio.js'
import path from 'path'

const RESPONSE_TIMEOUT = 1_000 // 1s
const START_DELAY = 1_000 // 1s
const TEST_TIMEOUT = 10_000 // 10s

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

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

const serverParameters: StdioServerParameters = {
  command: "node",
  args: [path.resolve(__dirname, '../dist/index.js')],
  env: process.env as Record<string, string>
}

describe('gmail-mcp e2e', () => {
  let client: StdioClientTransport

  let readMessages: ReadMessageType[] = []
  let errors: Error[] = []
  let clientClosed = true

  beforeAll(async () => {
    client = new StdioClientTransport(serverParameters)
    client.onmessage = (message) => readMessages.push(message as ReadMessageType)
    client.onerror = (error) => errors.push(error)
    client.onclose = () => clientClosed = true
  })

  beforeEach(async () => {
    readMessages = []
    errors = []
    if (clientClosed) {
      await client.start()
      clientClosed = false
      await delay(START_DELAY)
    }
  })

  afterAll(async () => {
    await client.close()
  })

  it('responds to ping', async () => {
    client.send({ jsonrpc: "2.0", id: 1, method: "ping" })
    await delay(RESPONSE_TIMEOUT)

    expect(readMessages).toHaveLength(1)
    expect(readMessages[0]).toEqual({ jsonrpc: '2.0', id: 1, result: { } })
    expect(errors).toHaveLength(0)
  })

  it('returns a list of tools', async () => {
    client.send({ jsonrpc: "2.0", id: 2, method: "tools/list" })
    await delay(RESPONSE_TIMEOUT)

    expect(readMessages).toHaveLength(1)
    expect(readMessages[0].result.tools?.length).toEqual(65)
  })

  it('can call the get_profile tool', async () => {
    client.send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "get_profile" } })
    await delay(RESPONSE_TIMEOUT)

    expect(readMessages).toHaveLength(1)
    expect(readMessages[0].result.content?.length).toEqual(1)

    const firstMessage = JSON.parse(readMessages[0].result.content?.[0].text ?? '{}')
    expect(firstMessage.emailAddress).toBeDefined()
    expect(firstMessage.messagesTotal).toBeDefined()
    expect(firstMessage.historyId).toBeDefined()
  })
})
