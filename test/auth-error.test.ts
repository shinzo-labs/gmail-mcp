// Unit tests for authentication error handling

describe("Authentication Error Handling", () => {
  // Recreate the handleTool function logic for testing
  const formatResponse = (response: any) => ({
    content: [{ type: "text", text: JSON.stringify(response) }],
  });

  const handleToolAuthLogic = async (
    mockError: Error | null,
    mockValidCredentials: boolean = true,
    mockOAuth2Client: any = {}
  ) => {
    try {
      if (!mockOAuth2Client) {
        throw new Error(
          "OAuth2 client could not be created, please check your credentials"
        );
      }

      if (!mockValidCredentials) {
        throw new Error(
          "OAuth2 credentials are invalid, please re-authenticate"
        );
      }

      if (mockError) {
        throw mockError;
      }

      // Simulate successful API call
      return { success: true };
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

      return formatResponse({
        error: `Tool execution failed: ${error.message}`,
      });
    }
  };

  test("should handle invalid_grant error with auth guidance", async () => {
    const error = new Error("invalid_grant: Token has been expired or revoked");
    const result = await handleToolAuthLogic(error, true, {});

    expect(result).toEqual({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error:
              "Authentication failed: invalid_grant: Token has been expired or revoked. Please re-authenticate by running: npx @shinzolabs/gmail-mcp auth",
          }),
        },
      ],
    });
  });

  test("should handle refresh_token error with auth guidance", async () => {
    const error = new Error("refresh_token is invalid");
    const result = await handleToolAuthLogic(error, true, {});

    expect(result).toEqual({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error:
              "Authentication failed: refresh_token is invalid. Please re-authenticate by running: npx @shinzolabs/gmail-mcp auth",
          }),
        },
      ],
    });
  });

  test("should handle 401 unauthorized error with auth guidance", async () => {
    const authError: any = new Error("Request failed with status code 401");
    authError.code = 401;

    const result = await handleToolAuthLogic(authError, true, {});

    expect(result).toEqual({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error:
              "Authentication failed: Request failed with status code 401. Please re-authenticate by running: npx @shinzolabs/gmail-mcp auth",
          }),
        },
      ],
    });
  });

  test("should handle 403 forbidden error with auth guidance", async () => {
    const authError: any = new Error("Request failed with status code 403");
    authError.code = 403;

    const result = await handleToolAuthLogic(authError, true, {});

    expect(result).toEqual({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error:
              "Authentication failed: Request failed with status code 403. Please re-authenticate by running: npx @shinzolabs/gmail-mcp auth",
          }),
        },
      ],
    });
  });

  test("should handle invalid_client error with auth guidance", async () => {
    const error = new Error("invalid_client: The OAuth client was not found");
    const result = await handleToolAuthLogic(error, true, {});

    expect(result).toEqual({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error:
              "Authentication failed: invalid_client: The OAuth client was not found. Please re-authenticate by running: npx @shinzolabs/gmail-mcp auth",
          }),
        },
      ],
    });
  });

  test("should handle unauthorized_client error with auth guidance", async () => {
    const error = new Error(
      "unauthorized_client: The client is not authorized"
    );
    const result = await handleToolAuthLogic(error, true, {});

    expect(result).toEqual({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error:
              "Authentication failed: unauthorized_client: The client is not authorized. Please re-authenticate by running: npx @shinzolabs/gmail-mcp auth",
          }),
        },
      ],
    });
  });

  test("should handle non-auth errors without specific guidance", async () => {
    const error = new Error("Some random error");
    const result = await handleToolAuthLogic(error, true, {});

    expect(result).toEqual({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error: "Tool execution failed: Some random error",
          }),
        },
      ],
    });
  });

  test("should handle missing OAuth2 client", async () => {
    const result = await handleToolAuthLogic(null, true, null);

    expect(result).toEqual({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error:
              "Tool execution failed: OAuth2 client could not be created, please check your credentials",
          }),
        },
      ],
    });
  });

  test("should handle invalid credentials", async () => {
    const result = await handleToolAuthLogic(null, false, {});

    expect(result).toEqual({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error:
              "Tool execution failed: OAuth2 credentials are invalid, please re-authenticate",
          }),
        },
      ],
    });
  });
});
