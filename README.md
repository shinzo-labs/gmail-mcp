# Gmail MCP

[![npm version](https://badge.fury.io/js/@shinzolabs%2Fgmail-mcp.svg)](https://badge.fury.io/js/@shinzolabs%2Fgmail-mcp)
[![smithery badge](https://smithery.ai/badge/@shinzo-labs/gmail-mcp)](https://smithery.ai/server/@shinzo-labs/gmail-mcp)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/introduction) implementation for the [Gmail](https://developers.google.com/gmail/api) API, providing a standardized interface for email management, sending, and retrieval.

## Features

- Complete Gmail API coverage including messages, threads, labels, drafts, and settings
- Support for sending, drafting, and managing emails
- Label management with customizable colors and visibility settings
- Thread operations for conversation management
- Settings management including vacation responder, IMAP/POP, and language settings
- History tracking for mailbox changes
- Secure OAuth2 authentication using your Google Cloud credentials

## Installation

⚠️ <strong>NOTE:</strong> Due to the large number of endpoints available on this server, it is recommended that you install and setup [Heimdall](https://github.com/shinzo-labs/heimdall) to limit the number of endpoints exposed to your client applications.

To use this MCP, you'll need to set up authentication with Gmail:

1. Go to the [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select an existing one
3. Enable the Gmail API for your project
4. Go to Credentials and create an OAuth 2.0 Client ID
   - Choose "Desktop app" as the application type (*Warning*: if you don't choose this type the server will not be able to parse the keys from your JSON file)
   - Download the client credentials JSON file
5. Save the downloaded credentials file to `~/.gmail-mcp/gcp-oauth.keys.json`

### NPX (Recommended)

Add the following to your MCP client `config.json` (`~/.heimdall/config.json` if using Heimdall):
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

### Manual Download

1. Download the repo:
```bash
git clone https://github.com/shinzo-labs/gmail-mcp.git
```

2. Install packages and build (inside cloned repo):
```bash
pnpm i && pnpm run build
```

3. Add the following to your MCP client `config.json` (`~/.heimdall/config.json` if using Heimdall):
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

### Smithery

To install for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@shinzo-labs/gmail-mcp):

```bash
npx -y @smithery/cli install @shinzo-labs/gmail-mcp --client claude
```

## Authentication

### Automated (recommended)

This MCP provides an automated authentication flow:

1. First, acquire OAuth credentials and download the JSON file.

2. Rename the JSON file to `gcp-oauth.keys.json` and copy it to `$HOME/.gmail-mcp/`, or wherever you've set it in `MCP_CONFIG_DIR`.

3. Run the authentication command:
```bash
# If using npx
npx @shinzolabs/gmail-mcp auth

# If in the project directory
pnpm i && pnpm run build && pnpm run auth
```

4. A browser window will automatically open to the Google OAuth consent screen
5. After granting access, you can close the browser window
6. The tokens will be automatically saved to `$HOME/.gmail-mcp/credentials.json`

The MCP will automatically:
- Manage token refresh
- Save credentials to disk
- Handle the OAuth callback
- Open the authentication URL in your default browser

Note: by default this server uses port `3000` to listen for the OAuth response. You can set `AUTH_SERVER_PORT` to something else if you are running another service on `3000`.

You can customize the config location by setting `MCP_CONFIG_DIR` before running the command (optional):
```bash
export MCP_CONFIG_DIR=/custom/path/to/directory/
```

### Manual (suggested for Docker usage)

If you wish, you may also provide credentials directly through the environment variables:
```bash
export CLIENT_ID=your-id
export CLIENT_SECRET=your-secret
export REFRESH_TOKEN=your-refresh-token
```

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

Contributions are welcomed and encouraged. Contact austin@shinzolabs.com with any questions, comments or concerns.
