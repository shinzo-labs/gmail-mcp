---
"@shinzolabs/gmail-mcp": minor
---

Add token optimization features to prevent LLM context window overflow

- Add new `get_message_summary` tool that returns only essential message fields (To, From, Subject, Date, body text) using ~100-200 tokens instead of 1,000-50,000+ tokens
- Add automatic pagination for `get_message`, `get_message_summary`, and `get_thread` tools with 22,500 token limit per response
- Include 250-token overlap between paginated chunks for context continuity
- Add `tokenOffset` parameter for fetching subsequent chunks of large messages/threads
- Update tool descriptions with context warnings about token usage
- Add `maxBodyLength` parameter to `get_message_summary` for body-level pagination
