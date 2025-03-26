#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_1 = require("@modelcontextprotocol/sdk/server/mcp");
const stdio_1 = require("@modelcontextprotocol/sdk/server/stdio");
const zod_1 = require("zod");
const googleapis_1 = require("googleapis");
const logger_1 = require("./logger");
const oauth2_1 = require("./oauth2");
const DEFAULT_HEADERS_LIST = [
    'Date',
    'From',
    'To',
    'Subject',
    'Message-ID',
    'In-Reply-To',
    'References'
];
const oauth2Client = (0, oauth2_1.createOAuth2Client)();
const server = new mcp_1.McpServer({
    name: "Gmail-MCP",
    version: "1.0.0",
    description: "An expansive MCP for the Gmail API"
});
const gmail = googleapis_1.google.gmail({ version: 'v1', auth: oauth2Client });
const formatResponse = (response) => ({
    content: [{ type: "text", text: JSON.stringify(response) }]
});
const handleTool = async (apiCall) => {
    (0, logger_1.logger)('info', 'Starting tool handler');
    try {
        const credentialsAreValid = await (0, oauth2_1.validateCredentials)(oauth2Client);
        if (!credentialsAreValid)
            throw new Error('No credentials found, you may need to run "npx @shinzolabs/gmail-mcp auth" to authenticate');
        const result = await apiCall();
        (0, logger_1.logger)('info', 'Tool execution completed successfully');
        return result;
    }
    catch (error) {
        (0, logger_1.logger)('error', `Tool execution failed: ${error.message}\n${error.stack}`);
        return `Tool execution failed: ${error.message}`;
    }
};
const decodedBody = (body) => {
    if (!body?.data)
        return body;
    (0, logger_1.logger)('debug', 'Decoding body', body);
    const decodedData = Buffer.from(body.data, 'base64').toString('utf-8');
    const decodedBody = {
        data: decodedData,
        size: body.data.length,
        attachmentId: body.attachmentId
    };
    (0, logger_1.logger)('debug', 'Decoded body', decodedBody);
    return decodedBody;
};
const processMessagePart = (messagePart, headersList = DEFAULT_HEADERS_LIST, includeBodyHtml = false) => {
    if ((messagePart.mimeType !== 'text/html' || includeBodyHtml) && messagePart.body) {
        messagePart.body = decodedBody(messagePart.body);
    }
    if (messagePart.parts) {
        messagePart.parts = messagePart.parts.map(part => processMessagePart(part, headersList, includeBodyHtml));
    }
    if (messagePart.headers) {
        messagePart.headers = messagePart.headers.filter(header => headersList.includes(header.name || ''));
    }
    return messagePart;
};
const getNestedHistory = (messagePart, level = 1) => {
    if (messagePart.mimeType === 'text/plain' && messagePart.body?.data) {
        const { data } = decodedBody(messagePart.body);
        if (!data)
            return '';
        const prefix = '>' + ' '.repeat(level);
        return data.split('\n').map(line => prefix + (line.startsWith('>') ? '' : ' ') + line).join('\n');
    }
    return (messagePart.parts || []).map(p => getNestedHistory(p, level + 1)).filter(p => p).join('\n');
};
const findHeader = (headers, name) => {
    if (!headers || !Array.isArray(headers) || !name)
        return null;
    return headers.find(h => h?.name?.toLowerCase() === name.toLowerCase())?.value;
};
const getQuotedContent = (thread) => {
    if (!thread.messages?.length)
        return '';
    const lastMessage = thread.messages[thread.messages.length - 1];
    if (!lastMessage?.payload)
        return '';
    let quotedContent = [];
    if (lastMessage.payload.headers) {
        const fromHeader = findHeader(lastMessage.payload.headers || [], 'from');
        const dateHeader = findHeader(lastMessage.payload.headers || [], 'date');
        if (fromHeader && dateHeader) {
            quotedContent.push('');
            quotedContent.push(`On ${dateHeader} ${fromHeader} wrote:`);
            quotedContent.push('');
        }
    }
    const nestedHistory = getNestedHistory(lastMessage.payload);
    if (nestedHistory) {
        quotedContent.push(nestedHistory);
        quotedContent.push(''); // Add extra newline for spacing between quotes
    }
    return quotedContent.join('\n');
};
const getThreadHeaders = (thread) => {
    let headers = [];
    if (!thread.messages?.length)
        return headers;
    const lastMessage = thread.messages[thread.messages.length - 1];
    const references = [];
    let subjectHeader = findHeader(lastMessage.payload?.headers || [], 'subject');
    if (subjectHeader) {
        if (!subjectHeader.toLowerCase().startsWith('re:')) {
            subjectHeader = `Re: ${subjectHeader}`;
        }
        headers.push(`Subject: ${subjectHeader}`);
    }
    const messageIdHeader = findHeader(lastMessage.payload?.headers || [], 'message-id');
    if (messageIdHeader) {
        headers.push(`In-Reply-To: ${messageIdHeader}`);
        references.push(messageIdHeader);
    }
    const referencesHeader = findHeader(lastMessage.payload?.headers || [], 'references');
    if (referencesHeader)
        references.unshift(...referencesHeader.split(' '));
    if (references.length > 0)
        headers.push(`References: ${references.join(' ')}`);
    return headers;
};
const constructRawMessage = async (params) => {
    (0, logger_1.logger)('debug', 'Constructing raw email message', { params });
    let thread = null;
    if (params.threadId) {
        const threadParams = { userId: 'me', id: params.threadId, format: 'full' };
        const { data } = await gmail.users.threads.get(threadParams);
        thread = data;
    }
    const message = [];
    if (params.to)
        message.push(`To: ${params.to}`);
    if (params.cc)
        message.push(`Cc: ${params.cc}`);
    if (params.bcc)
        message.push(`Bcc: ${params.bcc}`);
    if (thread)
        message.push(...getThreadHeaders(thread));
    message.push('Content-Type: text/plain charset="UTF-8"');
    message.push('MIME-Version: 1.0');
    message.push('');
    if (params.body)
        message.push(params.body);
    if (thread)
        message.push(getQuotedContent(thread));
    (0, logger_1.logger)('debug', 'Constructed raw email message', { message });
    return Buffer.from(message.join('\r\n')).toString('base64url');
};
server.tool("create_draft", "Create a draft email in Gmail", {
    raw: zod_1.z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format"),
    threadId: zod_1.z.string().optional().describe("The thread ID to associate this draft with"),
    to: zod_1.z.string().optional().describe("The recipient's email address"),
    cc: zod_1.z.string().optional().describe("The CC recipient's email address"),
    bcc: zod_1.z.string().optional().describe("The BCC recipient's email address"),
    subject: zod_1.z.string().optional().describe("The subject of the email"),
    body: zod_1.z.string().optional().describe("The body of the email"),
    attachments: zod_1.z.array(zod_1.z.object({
        filename: zod_1.z.string(),
        data: zod_1.z.string(),
        mimeType: zod_1.z.string()
    })).optional().describe("Array of attachments"),
    headersList: zod_1.z.array(zod_1.z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: zod_1.z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
}, async (params) => {
    return handleTool(async () => {
        let raw = params.raw;
        if (!raw)
            raw = await constructRawMessage(params);
        const draftCreateParams = { userId: 'me', requestBody: { message: { raw } } };
        if (params.threadId && draftCreateParams.requestBody?.message) {
            draftCreateParams.requestBody.message.threadId = params.threadId;
        }
        const { data } = await gmail.users.drafts.create(draftCreateParams);
        if (data.message?.payload) {
            data.message.payload = processMessagePart(data.message.payload, params.headersList, params.includeBodyHtml);
        }
        return formatResponse(data);
    });
});
server.tool("delete_draft", "Delete a draft", {
    id: zod_1.z.string().describe("The ID of the draft to delete")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.drafts.delete({ userId: 'me', id: params.id });
        return formatResponse(data);
    });
});
server.tool("get_draft", "Get a specific draft by ID", {
    id: zod_1.z.string().describe("The ID of the draft to retrieve"),
    headersList: zod_1.z.array(zod_1.z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: zod_1.z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.drafts.get({ userId: 'me', id: params.id, format: 'full' });
        if (data.message?.payload) {
            data.message.payload = processMessagePart(data.message.payload, params.headersList, params.includeBodyHtml);
        }
        return formatResponse(data);
    });
});
server.tool("list_drafts", "List drafts in the user's mailbox", {
    maxResults: zod_1.z.number().optional().describe("Maximum number of drafts to return. Accepts values between 1-500"),
    q: zod_1.z.string().optional().describe("Only return drafts matching the specified query. Supports the same query format as the Gmail search box"),
    includeSpamTrash: zod_1.z.boolean().optional().describe("Include drafts from SPAM and TRASH in the results"),
    includeBodyHtml: zod_1.z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large"),
    headersList: zod_1.z.array(zod_1.z.string()).optional().describe("List of headers to include in the return")
}, async (params) => {
    return handleTool(async () => {
        let drafts = [];
        const { data } = await gmail.users.drafts.list({ userId: 'me', ...params });
        drafts.push(...data.drafts || []);
        while (data.nextPageToken) {
            const { data: nextData } = await gmail.users.drafts.list({ userId: 'me', ...params, pageToken: data.nextPageToken });
            drafts.push(...nextData.drafts || []);
        }
        if (drafts) {
            drafts = drafts.map(draft => {
                if (draft.message?.payload) {
                    draft.message.payload = processMessagePart(draft.message.payload, params.headersList, params.includeBodyHtml);
                }
                return draft;
            });
        }
        return formatResponse(drafts);
    });
});
server.tool("send_draft", "Send an existing draft", {
    id: zod_1.z.string().describe("The ID of the draft to send")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.drafts.send({ userId: 'me', requestBody: { id: params.id } });
        return formatResponse(data);
    });
});
server.tool("update_draft", "Replace a draft's content", {
    id: zod_1.z.string().describe("The ID of the draft to update"),
    raw: zod_1.z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format"),
    threadId: zod_1.z.string().optional().describe("The thread ID to associate this draft with"),
    to: zod_1.z.string().optional().describe("The recipient's email address"),
    cc: zod_1.z.string().optional().describe("The CC recipient's email address"),
    bcc: zod_1.z.string().optional().describe("The BCC recipient's email address"),
    subject: zod_1.z.string().optional().describe("The subject of the email"),
    body: zod_1.z.string().optional().describe("The body of the email"),
    attachments: zod_1.z.array(zod_1.z.object({
        filename: zod_1.z.string(),
        data: zod_1.z.string(),
        mimeType: zod_1.z.string()
    })).optional().describe("Array of attachments"),
    headersList: zod_1.z.array(zod_1.z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: zod_1.z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
}, async (params) => {
    return handleTool(async () => {
        let raw = params.raw;
        if (!raw)
            raw = await constructRawMessage(params);
        const draftUpdateParams = { userId: 'me', id: params.id, requestBody: { message: { raw } } };
        if (params.threadId && draftUpdateParams.requestBody?.message) {
            draftUpdateParams.requestBody.message.threadId = params.threadId;
        }
        const { data } = await gmail.users.drafts.update(draftUpdateParams);
        if (data.message?.payload) {
            data.message.payload = processMessagePart(data.message.payload, params.headersList, params.includeBodyHtml);
        }
        return formatResponse(data);
    });
});
server.tool("create_label", "Create a new label", {
    name: zod_1.z.string().describe("The display name of the label"),
    messageListVisibility: zod_1.z.enum(['show', 'hide']).optional().describe("The visibility of messages with this label in the message list"),
    labelListVisibility: zod_1.z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("The visibility of the label in the label list"),
    color: zod_1.z.object({
        textColor: zod_1.z.string().describe("The text color of the label as hex string"),
        backgroundColor: zod_1.z.string().describe("The background color of the label as hex string")
    }).optional().describe("The color settings for the label")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.labels.create({ userId: 'me', requestBody: params });
        return formatResponse(data);
    });
});
server.tool("delete_label", "Delete a label", {
    id: zod_1.z.string().describe("The ID of the label to delete")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.labels.delete({ userId: 'me', id: params.id });
        return formatResponse(data);
    });
});
server.tool("get_label", "Get a specific label by ID", {
    id: zod_1.z.string().describe("The ID of the label to retrieve")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.labels.get({ userId: 'me', id: params.id });
        return formatResponse(data);
    });
});
server.tool("list_labels", "List all labels in the user's mailbox", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.labels.list({ userId: 'me' });
        return formatResponse(data);
    });
});
server.tool("patch_label", "Patch an existing label (partial update)", {
    id: zod_1.z.string().describe("The ID of the label to patch"),
    name: zod_1.z.string().optional().describe("The display name of the label"),
    messageListVisibility: zod_1.z.enum(['show', 'hide']).optional().describe("The visibility of messages with this label in the message list"),
    labelListVisibility: zod_1.z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("The visibility of the label in the label list"),
    color: zod_1.z.object({
        textColor: zod_1.z.string().describe("The text color of the label as hex string"),
        backgroundColor: zod_1.z.string().describe("The background color of the label as hex string")
    }).optional().describe("The color settings for the label")
}, async (params) => {
    const { id, ...labelData } = params;
    return handleTool(async () => {
        const { data } = await gmail.users.labels.patch({ userId: 'me', id, requestBody: labelData });
        return formatResponse(data);
    });
});
server.tool("update_label", "Update an existing label", {
    id: zod_1.z.string().describe("The ID of the label to update"),
    name: zod_1.z.string().optional().describe("The display name of the label"),
    messageListVisibility: zod_1.z.enum(['show', 'hide']).optional().describe("The visibility of messages with this label in the message list"),
    labelListVisibility: zod_1.z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("The visibility of the label in the label list"),
    color: zod_1.z.object({
        textColor: zod_1.z.string().describe("The text color of the label as hex string"),
        backgroundColor: zod_1.z.string().describe("The background color of the label as hex string")
    }).optional().describe("The color settings for the label")
}, async (params) => {
    const { id, ...labelData } = params;
    return handleTool(async () => {
        const { data } = await gmail.users.labels.update({ userId: 'me', id, requestBody: labelData });
        return formatResponse(data);
    });
});
server.tool("batch_delete_messages", "Delete multiple messages", {
    ids: zod_1.z.array(zod_1.z.string()).describe("The IDs of the messages to delete")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.messages.batchDelete({ userId: 'me', requestBody: { ids: params.ids } });
        return formatResponse(data);
    });
});
server.tool("batch_modify_messages", "Modify the labels on multiple messages", {
    ids: zod_1.z.array(zod_1.z.string()).describe("The IDs of the messages to modify"),
    addLabelIds: zod_1.z.array(zod_1.z.string()).optional().describe("A list of label IDs to add to the messages"),
    removeLabelIds: zod_1.z.array(zod_1.z.string()).optional().describe("A list of label IDs to remove from the messages")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.messages.batchModify({ userId: 'me', requestBody: { ids: params.ids, addLabelIds: params.addLabelIds, removeLabelIds: params.removeLabelIds } });
        return formatResponse(data);
    });
});
server.tool("delete_message", "Immediately and permanently delete a message", {
    id: zod_1.z.string().describe("The ID of the message to delete")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.messages.delete({ userId: 'me', id: params.id });
        return formatResponse(data);
    });
});
server.tool("get_message", "Get a specific message by ID with format options", {
    id: zod_1.z.string().describe("The ID of the message to retrieve"),
    headersList: zod_1.z.array(zod_1.z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: zod_1.z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.messages.get({ userId: 'me', id: params.id, format: 'full' });
        if (data.payload) {
            data.payload = processMessagePart(data.payload, params.headersList, params.includeBodyHtml);
        }
        return formatResponse(data);
    });
});
server.tool("list_messages", "List messages in the user's mailbox with optional filtering", {
    maxResults: zod_1.z.number().optional().describe("Maximum number of messages to return. Accepts values between 1-500"),
    pageToken: zod_1.z.string().optional().describe("Page token to retrieve a specific page of results"),
    q: zod_1.z.string().optional().describe("Only return messages matching the specified query. Supports the same query format as the Gmail search box"),
    labelIds: zod_1.z.array(zod_1.z.string()).optional().describe("Only return messages with labels that match all of the specified label IDs"),
    includeSpamTrash: zod_1.z.boolean().optional().describe("Include messages from SPAM and TRASH in the results"),
    includeBodyHtml: zod_1.z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large"),
    headersList: zod_1.z.array(zod_1.z.string()).optional().describe("List of headers to include in the return")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.messages.list({ userId: 'me', ...params });
        if (data.messages) {
            data.messages = data.messages.map((message) => {
                if (message.payload) {
                    message.payload = processMessagePart(message.payload, params.headersList, params.includeBodyHtml);
                }
                return message;
            });
        }
        return formatResponse(data);
    });
});
server.tool("modify_message", "Modify the labels on a message", {
    id: zod_1.z.string().describe("The ID of the message to modify"),
    addLabelIds: zod_1.z.array(zod_1.z.string()).optional().describe("A list of label IDs to add to the message"),
    removeLabelIds: zod_1.z.array(zod_1.z.string()).optional().describe("A list of label IDs to remove from the message")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.messages.modify({ userId: 'me', id: params.id, requestBody: { addLabelIds: params.addLabelIds, removeLabelIds: params.removeLabelIds } });
        return formatResponse(data);
    });
});
server.tool("send_message", "Send an email message to specified recipients", {
    raw: zod_1.z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format"),
    threadId: zod_1.z.string().optional().describe("The thread ID to associate this message with"),
    to: zod_1.z.string().optional().describe("The recipient's email address"),
    cc: zod_1.z.string().optional().describe("The CC recipient's email address"),
    bcc: zod_1.z.string().optional().describe("The BCC recipient's email address"),
    subject: zod_1.z.string().optional().describe("The subject of the email"),
    body: zod_1.z.string().optional().describe("The body of the email"),
    attachments: zod_1.z.array(zod_1.z.object({
        filename: zod_1.z.string(),
        data: zod_1.z.string(),
        mimeType: zod_1.z.string()
    })).optional().describe("Array of attachments"),
    headersList: zod_1.z.array(zod_1.z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: zod_1.z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
}, async (params) => {
    return handleTool(async () => {
        let raw = params.raw;
        if (!raw)
            raw = await constructRawMessage(params);
        const messageSendParams = { userId: 'me', requestBody: { raw } };
        if (params.threadId && messageSendParams.requestBody) {
            messageSendParams.requestBody.threadId = params.threadId;
        }
        const { data } = await gmail.users.messages.send(messageSendParams);
        if (data.payload) {
            data.payload = processMessagePart(data.payload, params.headersList, params.includeBodyHtml);
        }
        return formatResponse(data);
    });
});
server.tool("trash_message", "Move a message to the trash", {
    id: zod_1.z.string().describe("The ID of the message to move to trash")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.messages.trash({ userId: 'me', id: params.id });
        return formatResponse(data);
    });
});
server.tool("untrash_message", "Remove a message from the trash", {
    id: zod_1.z.string().describe("The ID of the message to remove from trash")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.messages.untrash({ userId: 'me', id: params.id });
        return formatResponse(data);
    });
});
server.tool("get_attachment", "Get a message attachment", {
    messageId: zod_1.z.string().describe("ID of the message containing the attachment"),
    id: zod_1.z.string().describe("The ID of the attachment"),
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.messages.attachments.get({ userId: 'me', messageId: params.messageId, id: params.id });
        return formatResponse(data);
    });
});
server.tool("delete_thread", "Delete a thread", {
    id: zod_1.z.string().describe("The ID of the thread to delete")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.threads.delete({ userId: 'me', id: params.id });
        return formatResponse(data);
    });
});
server.tool("get_thread", "Get a specific thread by ID", {
    id: zod_1.z.string().describe("The ID of the thread to retrieve"),
    headersList: zod_1.z.array(zod_1.z.string()).optional().describe("List of headers to include in the return"),
    includeBodyHtml: zod_1.z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.threads.get({ userId: 'me', id: params.id, format: 'full' });
        if (data.messages) {
            data.messages = data.messages.map(message => {
                if (message.payload) {
                    message.payload = processMessagePart(message.payload, params.headersList, params.includeBodyHtml);
                }
                return message;
            });
        }
        return formatResponse(data);
    });
});
server.tool("list_threads", "List threads in the user's mailbox", {
    maxResults: zod_1.z.number().optional().describe("Maximum number of threads to return"),
    pageToken: zod_1.z.string().optional().describe("Page token to retrieve a specific page of results"),
    q: zod_1.z.string().optional().describe("Only return threads matching the specified query"),
    labelIds: zod_1.z.array(zod_1.z.string()).optional().describe("Only return threads with labels that match all of the specified label IDs"),
    includeSpamTrash: zod_1.z.boolean().optional().describe("Include threads from SPAM and TRASH in the results"),
    includeBodyHtml: zod_1.z.boolean().optional().describe("Whether to include the parsed HTML in the return each body, excluded by default because they can be excessively large"),
    headersList: zod_1.z.array(zod_1.z.string()).optional().describe("List of headers to include in the return")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.threads.list({ userId: 'me', ...params });
        if (data.threads) {
            data.threads = data.threads.map(thread => {
                if (thread.messages) {
                    thread.messages = thread.messages.map(message => {
                        if (message.payload) {
                            message.payload = processMessagePart(message.payload, params.headersList, params.includeBodyHtml);
                        }
                        return message;
                    });
                }
                return thread;
            });
        }
        return formatResponse(data);
    });
});
server.tool("modify_thread", "Modify the labels applied to a thread", {
    id: zod_1.z.string().describe("The ID of the thread to modify"),
    addLabelIds: zod_1.z.array(zod_1.z.string()).optional().describe("A list of label IDs to add to the thread"),
    removeLabelIds: zod_1.z.array(zod_1.z.string()).optional().describe("A list of label IDs to remove from the thread")
}, async (params) => {
    const { id, ...threadData } = params;
    return handleTool(async () => {
        const { data } = await gmail.users.threads.modify({ userId: 'me', id, requestBody: threadData });
        return formatResponse(data);
    });
});
server.tool("trash_thread", "Move a thread to the trash", {
    id: zod_1.z.string().describe("The ID of the thread to move to trash")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.threads.trash({ userId: 'me', id: params.id });
        return formatResponse(data);
    });
});
server.tool("untrash_thread", "Remove a thread from the trash", {
    id: zod_1.z.string().describe("The ID of the thread to remove from trash")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.threads.untrash({ userId: 'me', id: params.id });
        return formatResponse(data);
    });
});
server.tool("get_auto_forwarding", "Gets auto-forwarding settings", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.getAutoForwarding({ userId: 'me' });
        return formatResponse(data);
    });
});
server.tool("get_imap", "Gets IMAP settings", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.getImap({ userId: 'me' });
        return formatResponse(data);
    });
});
server.tool("get_language", "Gets language settings", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.getLanguage({ userId: 'me' });
        return formatResponse(data);
    });
});
server.tool("get_pop", "Gets POP settings", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.getPop({ userId: 'me' });
        return formatResponse(data);
    });
});
server.tool("get_vacation", "Get vacation responder settings", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.getVacation({ userId: 'me' });
        return formatResponse(data);
    });
});
server.tool("update_auto_forwarding", "Updates automatic forwarding settings", {
    enabled: zod_1.z.boolean().describe("Whether all incoming mail is automatically forwarded to another address"),
    emailAddress: zod_1.z.string().describe("Email address to which messages should be automatically forwarded"),
    disposition: zod_1.z.enum(['leaveInInbox', 'archive', 'trash', 'markRead']).describe("The state in which messages should be left after being forwarded")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.updateAutoForwarding({ userId: 'me', requestBody: params });
        return formatResponse(data);
    });
});
server.tool("update_imap", "Updates IMAP settings", {
    enabled: zod_1.z.boolean().describe("Whether IMAP is enabled for the account"),
    expungeBehavior: zod_1.z.enum(['archive', 'trash', 'deleteForever']).optional().describe("The action that will be executed on a message when it is marked as deleted and expunged from the last visible IMAP folder"),
    maxFolderSize: zod_1.z.number().optional().describe("An optional limit on the number of messages that can be accessed through IMAP")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.updateImap({ userId: 'me', requestBody: params });
        return formatResponse(data);
    });
});
server.tool("update_language", "Updates language settings", {
    displayLanguage: zod_1.z.string().describe("The language to display Gmail in, formatted as an RFC 3066 Language Tag")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.updateLanguage({ userId: 'me', requestBody: params });
        return formatResponse(data);
    });
});
server.tool("update_pop", "Updates POP settings", {
    accessWindow: zod_1.z.enum(['disabled', 'allMail', 'fromNowOn']).describe("The range of messages which are accessible via POP"),
    disposition: zod_1.z.enum(['archive', 'trash', 'leaveInInbox']).describe("The action that will be executed on a message after it has been fetched via POP")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.updatePop({ userId: 'me', requestBody: params });
        return formatResponse(data);
    });
});
server.tool("update_vacation", "Update vacation responder settings", {
    enableAutoReply: zod_1.z.boolean().describe("Whether the vacation responder is enabled"),
    responseSubject: zod_1.z.string().optional().describe("Optional subject line for the vacation responder auto-reply"),
    responseBodyPlainText: zod_1.z.string().describe("Response body in plain text format"),
    restrictToContacts: zod_1.z.boolean().optional().describe("Whether responses are only sent to contacts"),
    restrictToDomain: zod_1.z.boolean().optional().describe("Whether responses are only sent to users in the same domain"),
    startTime: zod_1.z.string().optional().describe("Start time for sending auto-replies (epoch ms)"),
    endTime: zod_1.z.string().optional().describe("End time for sending auto-replies (epoch ms)")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.updateVacation({ userId: 'me', requestBody: params });
        return formatResponse(data);
    });
});
server.tool("add_delegate", "Adds a delegate to the specified account", {
    delegateEmail: zod_1.z.string().describe("Email address of delegate to add")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.delegates.create({ userId: 'me', requestBody: { delegateEmail: params.delegateEmail } });
        return formatResponse(data);
    });
});
server.tool("remove_delegate", "Removes the specified delegate", {
    delegateEmail: zod_1.z.string().describe("Email address of delegate to remove")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.delegates.delete({ userId: 'me', delegateEmail: params.delegateEmail });
        return formatResponse(data);
    });
});
server.tool("get_delegate", "Gets the specified delegate", {
    delegateEmail: zod_1.z.string().describe("The email address of the delegate to retrieve")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.delegates.get({ userId: 'me', delegateEmail: params.delegateEmail });
        return formatResponse(data);
    });
});
server.tool("list_delegates", "Lists the delegates for the specified account", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.delegates.list({ userId: 'me' });
        return formatResponse(data);
    });
});
server.tool("create_filter", "Creates a filter", {
    criteria: zod_1.z.object({
        from: zod_1.z.string().optional().describe("The sender's display name or email address"),
        to: zod_1.z.string().optional().describe("The recipient's display name or email address"),
        subject: zod_1.z.string().optional().describe("Case-insensitive phrase in the message's subject"),
        query: zod_1.z.string().optional().describe("A Gmail search query that specifies the filter's criteria"),
        negatedQuery: zod_1.z.string().optional().describe("A Gmail search query that specifies criteria the message must not match"),
        hasAttachment: zod_1.z.boolean().optional().describe("Whether the message has any attachment"),
        excludeChats: zod_1.z.boolean().optional().describe("Whether the response should exclude chats"),
        size: zod_1.z.number().optional().describe("The size of the entire RFC822 message in bytes"),
        sizeComparison: zod_1.z.enum(['smaller', 'larger']).optional().describe("How the message size in bytes should be in relation to the size field")
    }).describe("Filter criteria"),
    action: zod_1.z.object({
        addLabelIds: zod_1.z.array(zod_1.z.string()).optional().describe("List of labels to add to messages"),
        removeLabelIds: zod_1.z.array(zod_1.z.string()).optional().describe("List of labels to remove from messages"),
        forward: zod_1.z.string().optional().describe("Email address that the message should be forwarded to")
    }).describe("Actions to perform on messages matching the criteria")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.filters.create({ userId: 'me', requestBody: params });
        return formatResponse(data);
    });
});
server.tool("delete_filter", "Deletes a filter", {
    id: zod_1.z.string().describe("The ID of the filter to be deleted")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.filters.delete({ userId: 'me', id: params.id });
        return formatResponse(data);
    });
});
server.tool("get_filter", "Gets a filter", {
    id: zod_1.z.string().describe("The ID of the filter to be fetched")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.filters.get({ userId: 'me', id: params.id });
        return formatResponse(data);
    });
});
server.tool("list_filters", "Lists the message filters of a Gmail user", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.filters.list({ userId: 'me' });
        return formatResponse(data);
    });
});
server.tool("create_forwarding_address", "Creates a forwarding address", {
    forwardingEmail: zod_1.z.string().describe("An email address to which messages can be forwarded")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.forwardingAddresses.create({ userId: 'me', requestBody: params });
        return formatResponse(data);
    });
});
server.tool("delete_forwarding_address", "Deletes the specified forwarding address", {
    forwardingEmail: zod_1.z.string().describe("The forwarding address to be deleted")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.forwardingAddresses.delete({ userId: 'me', forwardingEmail: params.forwardingEmail });
        return formatResponse(data);
    });
});
server.tool("get_forwarding_address", "Gets the specified forwarding address", {
    forwardingEmail: zod_1.z.string().describe("The forwarding address to be retrieved")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.forwardingAddresses.get({ userId: 'me', forwardingEmail: params.forwardingEmail });
        return formatResponse(data);
    });
});
server.tool("list_forwarding_addresses", "Lists the forwarding addresses for the specified account", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.forwardingAddresses.list({ userId: 'me' });
        return formatResponse(data);
    });
});
server.tool("create_send_as", "Creates a custom send-as alias", {
    sendAsEmail: zod_1.z.string().describe("The email address that appears in the 'From:' header"),
    displayName: zod_1.z.string().optional().describe("A name that appears in the 'From:' header"),
    replyToAddress: zod_1.z.string().optional().describe("An optional email address that is included in a 'Reply-To:' header"),
    signature: zod_1.z.string().optional().describe("An optional HTML signature"),
    isPrimary: zod_1.z.boolean().optional().describe("Whether this address is the primary address"),
    treatAsAlias: zod_1.z.boolean().optional().describe("Whether Gmail should treat this address as an alias")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.create({ userId: 'me', requestBody: params });
        return formatResponse(data);
    });
});
server.tool("delete_send_as", "Deletes the specified send-as alias", {
    sendAsEmail: zod_1.z.string().describe("The send-as alias to be deleted")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.delete({ userId: 'me', sendAsEmail: params.sendAsEmail });
        return formatResponse(data);
    });
});
server.tool("get_send_as", "Gets the specified send-as alias", {
    sendAsEmail: zod_1.z.string().describe("The send-as alias to be retrieved")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.get({ userId: 'me', sendAsEmail: params.sendAsEmail });
        return formatResponse(data);
    });
});
server.tool("list_send_as", "Lists the send-as aliases for the specified account", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.list({ userId: 'me' });
        return formatResponse(data);
    });
});
server.tool("patch_send_as", "Patches the specified send-as alias", {
    sendAsEmail: zod_1.z.string().describe("The send-as alias to be updated"),
    displayName: zod_1.z.string().optional().describe("A name that appears in the 'From:' header"),
    replyToAddress: zod_1.z.string().optional().describe("An optional email address that is included in a 'Reply-To:' header"),
    signature: zod_1.z.string().optional().describe("An optional HTML signature"),
    isPrimary: zod_1.z.boolean().optional().describe("Whether this address is the primary address"),
    treatAsAlias: zod_1.z.boolean().optional().describe("Whether Gmail should treat this address as an alias")
}, async (params) => {
    const { sendAsEmail, ...patchData } = params;
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.patch({ userId: 'me', sendAsEmail, requestBody: patchData });
        return formatResponse(data);
    });
});
server.tool("update_send_as", "Updates a send-as alias", {
    sendAsEmail: zod_1.z.string().describe("The send-as alias to be updated"),
    displayName: zod_1.z.string().optional().describe("A name that appears in the 'From:' header"),
    replyToAddress: zod_1.z.string().optional().describe("An optional email address that is included in a 'Reply-To:' header"),
    signature: zod_1.z.string().optional().describe("An optional HTML signature"),
    isPrimary: zod_1.z.boolean().optional().describe("Whether this address is the primary address"),
    treatAsAlias: zod_1.z.boolean().optional().describe("Whether Gmail should treat this address as an alias")
}, async (params) => {
    const { sendAsEmail, ...updateData } = params;
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.update({ userId: 'me', sendAsEmail, requestBody: updateData });
        return formatResponse(data);
    });
});
server.tool("verify_send_as", "Sends a verification email to the specified send-as alias", {
    sendAsEmail: zod_1.z.string().describe("The send-as alias to be verified")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.verify({ userId: 'me', sendAsEmail: params.sendAsEmail });
        return formatResponse(data);
    });
});
server.tool("delete_smime_info", "Deletes the specified S/MIME config for the specified send-as alias", {
    sendAsEmail: zod_1.z.string().describe("The email address that appears in the 'From:' header"),
    id: zod_1.z.string().describe("The immutable ID for the S/MIME config")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.delete({ userId: 'me', sendAsEmail: params.sendAsEmail, id: params.id });
        return formatResponse(data);
    });
});
server.tool("get_smime_info", "Gets the specified S/MIME config for the specified send-as alias", {
    sendAsEmail: zod_1.z.string().describe("The email address that appears in the 'From:' header"),
    id: zod_1.z.string().describe("The immutable ID for the S/MIME config")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.get({ userId: 'me', sendAsEmail: params.sendAsEmail, id: params.id });
        return formatResponse(data);
    });
});
server.tool("insert_smime_info", "Insert (upload) the given S/MIME config for the specified send-as alias", {
    sendAsEmail: zod_1.z.string().describe("The email address that appears in the 'From:' header"),
    encryptedKeyPassword: zod_1.z.string().describe("Encrypted key password"),
    pkcs12: zod_1.z.string().describe("PKCS#12 format containing a single private/public key pair and certificate chain")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.insert({ userId: 'me', sendAsEmail: params.sendAsEmail, requestBody: params });
        return formatResponse(data);
    });
});
server.tool("list_smime_info", "Lists S/MIME configs for the specified send-as alias", {
    sendAsEmail: zod_1.z.string().describe("The email address that appears in the 'From:' header")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.list({ userId: 'me', sendAsEmail: params.sendAsEmail });
        return formatResponse(data);
    });
});
server.tool("set_default_smime_info", "Sets the default S/MIME config for the specified send-as alias", {
    sendAsEmail: zod_1.z.string().describe("The email address that appears in the 'From:' header"),
    id: zod_1.z.string().describe("The immutable ID for the S/MIME config")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.setDefault({ userId: 'me', sendAsEmail: params.sendAsEmail, id: params.id });
        return formatResponse(data);
    });
});
server.tool("get_profile", "Get the current user's Gmail profile", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.getProfile({ userId: 'me' });
        return formatResponse(data);
    });
});
server.tool("watch_mailbox", "Watch for changes to the user's mailbox", {
    topicName: zod_1.z.string().describe("The name of the Cloud Pub/Sub topic to publish notifications to"),
    labelIds: zod_1.z.array(zod_1.z.string()).optional().describe("Label IDs to restrict notifications to"),
    labelFilterAction: zod_1.z.enum(['include', 'exclude']).optional().describe("Whether to include or exclude the specified labels")
}, async (params) => {
    return handleTool(async () => {
        const { data } = await gmail.users.watch({ userId: 'me', requestBody: params });
        return formatResponse(data);
    });
});
server.tool("stop_mail_watch", "Stop receiving push notifications for the given user mailbox", {}, async () => {
    return handleTool(async () => {
        const { data } = await gmail.users.stop({ userId: 'me' });
        return formatResponse(data);
    });
});
const main = async () => {
    if (process.argv[2] === 'auth') {
        await (0, oauth2_1.launchAuthServer)(oauth2Client);
        process.exit(0);
    }
    const transport = new stdio_1.StdioServerTransport();
    await server.connect(transport);
};
main();
