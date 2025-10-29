---
"@shinzolabs/gmail-mcp": minor
---

Add token optimization features for LLM context management

- Add get_message_summary tool returning essential fields only
- Add automatic pagination to get_message, get_message_summary, and get_thread
- Implement 22,500 token limit with 250-token overlap between chunks
- Add pageToken parameter for fetching subsequent chunks
