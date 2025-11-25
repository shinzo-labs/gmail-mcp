<div align="center">
    <h1 align="center">Gmail MCP Server</h1>
    <p align=center>
        <a href="https://badge.fury.io/js/@shinzolabs%2Fgmail-mcp"><img src="https://badge.fury.io/js/@shinzolabs%2Fgmail-mcp.svg" alt="NPM Version"></a>
        <a href="https://github.com/shinzo-labs/gmail-mcp/stargazers"><img src="https://img.shields.io/github/stars/shinzo-labs/gmail-mcp?style=flat&logo=github&color=e3b341" alt="Stars"></a>
        <a href="https://github.com/shinzo-labs/gmail-mcp/forks"><img src="https://img.shields.io/github/forks/shinzo-labs/gmail-mcp?style=flat&logo=github&color=8957e5" alt="Forks"></a>
        <a href="https://smithery.ai/server/@shinzo-labs/gmail-mcp"><img src="https://smithery.ai/badge/@shinzo-labs/gmail-mcp" alt="Smithery Calls"></a>
        <a href="https://www.npmjs.com/package/@shinzolabs/gmail-mcp"><img src="https://img.shields.io/npm/dm/%40shinzolabs%2Fgmail-mcp" alt="NPM Downloads"></a>
</div>

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/introduction) server implementation for the [Gmail](https://developers.google.com/gmail/api) API, providing a standardized interface for email management, sending, and retrieval.

<p align="center"><img height="512" src=https://github.com/user-attachments/assets/b61db02e-bde4-4386-b5a9-2b1c6a989925></p>

## Features

- Complete Gmail API coverage including messages, threads, labels, drafts, and settings
- Support for sending, drafting, and managing emails
- Label management with customizable colors and visibility settings
- Thread operations for conversation management
- Settings management including vacation responder, IMAP/POP, and language settings
- History tracking for mailbox changes
- Secure OAuth2 authentication using Google Cloud credentials

## Prerequisites

### Dependencies

For simplest installation, install [Node.js 18+](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm). If you would like to build locally, you will also need to install [pnpm](https://pnpm.io/installation).

### Google Workspace Setup

To run this MCP server, you will need to set up a Google API Client for your organization, with each user running a script to retrieve their own OAuth refresh token.

#### Google API Client Setup (once per organization)

1. Go to the [Google Cloud Console](https://console.cloud.google.com).
2. Create a new project or select an existing one.
3. Enable the Gmail API for your project.
4. Go to Credentials and create an OAuth 2.0 Client ID. Choose "Desktop app" for the client type.
5. Download and save the OAuth keys JSON as `~/.gmail-mcp/gcp-oauth.keys.json`. ⚠️ NOTE: to create `~/.gmail-mcp/` through MacOS's Finder app you need to [enable hidden files](https://stackoverflow.com/questions/5891365/mac-os-x-doesnt-allow-to-name-files-starting-with-a-dot-how-do-i-name-the-hta) first.
6. (Optional) For remote server installation (ex. using Smithery CLI), note the `CLIENT_ID` and `CLIENT_SECRET` from this file.

#### Client OAuth (once per user)

1. Have the user copy `~/.gmail-mcp/gcp-oauth.keys.json` to their computer at the same path.
2. Run `npx @shinzolabs/gmail-mcp auth`.
3. A browser window will open where the user may select a profile, review the requested scopes, and approve.
4. (Optional) For remote server installation, note the file path mentioned in the success message (`~/.gmail-mcp/credentials.json` by default). The user's `REFRESH_TOKEN` will be found here.

## Client Configuration

There are several options to configure your MCP client with the server. For hosted/remote server setup, use Smithery's CLI with a [Smithery API Key](https://smithery.ai/docs/registry#registry-api). For local installation, use `npx` or build from source. Each of these options is explained below.

### Smithery Remote Server (Recommended)

To add a remote server to your MCP client `config.json`, run the following command from [Smithery CLI](https://github.com/smithery-ai/cli?tab=readme-ov-file#smithery-cli--):

```bash
npx -y @smithery/cli install @shinzo-labs/gmail-mcp
```

Enter your `CLIENT_ID`, `CLIENT_SECRET`, and `REFRESH_TOKEN` when prompted.

### Smithery SDK

If you are developing your own agent application, you can use the boilerplate code [here](https://smithery.ai/server/@shinzo-labs/gmail-mcp/api).

### NPX Local Install

To install the server locally with `npx`, add the following to your MCP client `config.json`:
```javascript
{
  "mcpServers": {
    "gmail": {
      "command": "npx",
      "args": [
        "@shinzolabs/gmail-mcp"
      ]
    }
  }
}
```

### Build from Source

1. Download the repo:
```bash
git clone https://github.com/shinzo-labs/gmail-mcp.git
```

2. Install packages and build with `pnpm` (inside cloned repo):
```bash
pnpm i && pnpm build
```

3. Add the following to your MCP client `config.json`:
```javascript
{
  "mcpServers": {
    "gmail": {
      "command": "node",
      "args": [
        "/path/to/gmail-mcp/dist/index.js"
      ]
    }
  }
}
```

## Config Variables

| Variable                 | Description                                             | Required?                       | Default                              |
|--------------------------|---------------------------------------------------------|---------------------------------|--------------------------------------|
| `AUTH_SERVER_PORT`       | Port for the temporary OAuth authentication server      | No                              | `3000`                               |
| `CLIENT_ID`              | Google API client ID (found in `GMAIL_OAUTH_PATH`)      | Yes if remote server connection | `''`                                 |
| `CLIENT_SECRET`          | Google API client secret (found in `GMAIL_OAUTH_PATH`)  | Yes if remote server connection | `''`                                 |
| `GMAIL_CREDENTIALS_PATH` | Path to the user credentials file                       | No                              | `MCP_CONFIG_DIR/credentials.json`    |
| `GMAIL_OAUTH_PATH`       | Path to the Google API Client file                      | No                              | `MCP_CONFIG_DIR/gcp-oauth.keys.json` |
| `MCP_CONFIG_DIR`         | Directory for storing configuration files               | No                              | `~/.gmail-mcp`                       |
| `REFRESH_TOKEN`          | OAuth refresh token (found in `GMAIL_CREDENTIALS_PATH`) | Yes if remote server connection | `''`                                 |
| `PORT`                   | Port for Streamable HTTP transport method               | No                              | `3000`                               |
| `TELEMETRY_ENABLED`      | Enable telemetry                                        | No                              | `true`                               |

## Supported Endpoints

### User Management
- `get_profile`: Get the current user's Gmail profile
- `stop_mail_watch`: Stop receiving push notifications
- `watch_mailbox`: Set up push notifications for mailbox changes

### Message Management

#### Managing Messages
- `list_messages`: List messages with optional filtering
- `get_message`: Get a specific message
- `get_attachment`: Get a message attachment
- `modify_message`: Modify message labels
- `send_message`: Send an email message to specified recipients
- `delete_message`: Permanently delete a message
- `trash_message`: Move message to trash
- `untrash_message`: Remove message from trash
- `batch_modify_messages`: Modify multiple messages
- `batch_delete_messages`: Delete multiple messages

### Label Management
- `list_labels`: List all labels
- `get_label`: Get a specific label
- `create_label`: Create a new label
- `update_label`: Update a label
- `patch_label`: Partial update of a label
- `delete_label`: Delete a label

### Thread Management
- `list_threads`: List email threads
- `get_thread`: Get a specific thread
- `modify_thread`: Modify thread labels
- `trash_thread`: Move thread to trash
- `untrash_thread`: Remove thread from trash
- `delete_thread`: Delete a thread

### Draft Management
- `list_drafts`: List drafts in the user's mailbox
- `get_draft`: Get a specific draft by ID
- `create_draft`: Create a draft email in Gmail
- `update_draft`: Replace a draft's content
- `delete_draft`: Delete a draft
- `send_draft`: Send an existing draft

### Settings Management

#### Auto-Forwarding
- `get_auto_forwarding`: Get auto-forwarding settings
- `update_auto_forwarding`: Update auto-forwarding settings

#### IMAP Settings
- `get_imap`: Get IMAP settings
- `update_imap`: Update IMAP settings

#### POP Settings
- `get_pop`: Get POP settings
- `update_pop`: Update POP settings

#### Vacation Responder
- `get_vacation`: Get vacation responder settings
- `update_vacation`: Update vacation responder

#### Language Settings
- `get_language`: Get language settings
- `update_language`: Update language settings

#### Delegates
- `list_delegates`: List account delegates
- `get_delegate`: Get a specific delegate
- `add_delegate`: Add a delegate
- `remove_delegate`: Remove a delegate

#### Filters
- `list_filters`: List email filters
- `get_filter`: Get a specific filter
- `create_filter`: Create a new filter
- `delete_filter`: Delete a filter

#### Forwarding Addresses
- `list_forwarding_addresses`: List forwarding addresses
- `get_forwarding_address`: Get a specific forwarding address
- `create_forwarding_address`: Create a forwarding address
- `delete_forwarding_address`: Delete a forwarding address

#### Send-As Settings
- `list_send_as`: List send-as aliases
- `get_send_as`: Get a specific send-as alias
- `create_send_as`: Create a send-as alias
- `update_send_as`: Update a send-as alias
- `patch_send_as`: Partial update of a send-as alias
- `verify_send_as`: Send verification email
- `delete_send_as`: Delete a send-as alias

#### S/MIME Settings
- `list_smime_info`: List S/MIME configurations
- `get_smime_info`: Get a specific S/MIME config
- `insert_smime_info`: Upload a new S/MIME config
- `set_default_smime_info`: Set default S/MIME config
- `delete_smime_info`: Delete an S/MIME config

## Contributing

Contributions are welcomed and encouraged! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on issues, contributions, and contact information.

## Data Collection and Privacy

Shinzo Labs collects limited anonymous telemetry from this server to help improve our products and services. No personally identifiable information is collected as part of this process. Please review the [Privacy Policy](./PRIVACY.md) for more details on the types of data collected and how to opt-out of this telemetry.

## License

MIT
