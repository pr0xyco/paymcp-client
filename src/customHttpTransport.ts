import { StreamableHTTPClientTransportOptions, StreamableHTTPError, StreamableHTTPReconnectionOptions } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { FetchLike } from './types.js';
import { isInitializedNotification, isJSONRPCRequest, isJSONRPCResponse, JSONRPCMessage, JSONRPCMessageSchema } from '@modelcontextprotocol/sdk/types.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
//import { auth, AuthResult, UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { EventSourceParserStream } from "eventsource-parser/stream"; // Transivitive depdendency of @modelcontextprotocol/sdk

// Adapted from https://github.com/modelcontextprotocol/typescript-sdk/blob/df0d9c4ffc773b6414ba84bef3f016cf97e8cdd4/src/client/streamableHttp.ts#L80
// Add support for custom fetch, our OAuth plumbing
// Remove support for MCP SDK OAuth

// Default reconnection options for StreamableHTTP connections
const DEFAULT_STREAMABLE_HTTP_RECONNECTION_OPTIONS: StreamableHTTPReconnectionOptions = {
  initialReconnectionDelay: 1000,
  maxReconnectionDelay: 30000,
  reconnectionDelayGrowFactor: 1.5,
  maxRetries: 2,
};

/**
 * Client transport for Streamable HTTP: this implements the MCP Streamable HTTP transport specification.
 * It will connect to a server using HTTP POST for sending messages and HTTP GET with Server-Sent Events
 * for receiving messages.
 */
export class CustomHTTPTransport implements Transport {
  private _fetchFn: FetchLike;
  private _abortController?: AbortController;
  private _url: URL;
  //private _resourceMetadataUrl?: URL;
  private _requestInit?: RequestInit;
  //private _authProvider?: OAuthClientProvider;
  private _sessionId?: string;
  private _reconnectionOptions: StreamableHTTPReconnectionOptions;

  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  constructor(
    fetchFn: FetchLike,
    url: URL,
    opts?: StreamableHTTPClientTransportOptions,
  ) {
    this._fetchFn = fetchFn;
    this._url = url;
    //this._resourceMetadataUrl = undefined;
    this._requestInit = opts?.requestInit;
    //this._authProvider = opts?.authProvider;
    this._sessionId = opts?.sessionId;
    this._reconnectionOptions = opts?.reconnectionOptions ?? DEFAULT_STREAMABLE_HTTP_RECONNECTION_OPTIONS;
    if (opts?.authProvider) {
      throw new Error('Novellum customHTTPTransport does not support authProvider')
    }
  }

  /*private async _authThenStart(): Promise<void> {
    if (!this._authProvider) {
      throw new UnauthorizedError("No auth provider");
    }

    let result: AuthResult;
    try {
      result = await auth(this._authProvider, { serverUrl: this._url, resourceMetadataUrl: this._resourceMetadataUrl });
    } catch (error) {
      this.onerror?.(error as Error);
      throw error;
    }

    if (result !== "AUTHORIZED") {
      throw new UnauthorizedError();
    }

    return await this._startOrAuthSse({ resumptionToken: undefined });
  }*/

  private async _commonHeaders(): Promise<Headers> {
    const headers: HeadersInit = {};
    /*if (this._authProvider) {
      const tokens = await this._authProvider.tokens();
      if (tokens) {
        headers["Authorization"] = `Bearer ${tokens.access_token}`;
      }
    }*/

    if (this._sessionId) {
      headers["mcp-session-id"] = this._sessionId;
    }

    return new Headers(
      { ...headers, ...this._requestInit?.headers }
    );
  }


  private async _startOrAuthSse(options: { resumptionToken?: string, onresumptiontoken?: (token: string) => void, replayMessageId?: string | number }): Promise<void> {
    const { resumptionToken } = options;
    try {
      // Try to open an initial SSE stream with GET to listen for server messages
      // This is optional according to the spec - server may not support it
      const headers = await this._commonHeaders();
      headers.set("Accept", "text/event-stream");

      // Include Last-Event-ID header for resumable streams if provided
      if (resumptionToken) {
        headers.set("last-event-id", resumptionToken);
      }

      const response = await this._fetchFn(this._url.toString(), {
        method: "GET",
        headers,
        signal: this._abortController?.signal,
      });

      if (!response.ok) {
        /*if (response.status === 401 && this._authProvider) {
          // Need to authenticate
          return await this._authThenStart();
        }*/

        // 405 indicates that the server does not offer an SSE stream at GET endpoint
        // This is an expected case that should not trigger an error
        if (response.status === 405) {
          return;
        }

        throw new StreamableHTTPError(
          response.status,
          `Failed to open SSE stream: ${response.statusText}`,
        );
      }

      this._handleSseStream(response.body, options);
    } catch (error) {
      this.onerror?.(error as Error);
      throw error;
    }
  }


  /**
   * Calculates the next reconnection delay using  backoff algorithm
   *
   * @param attempt Current reconnection attempt count for the specific stream
   * @returns Time to wait in milliseconds before next reconnection attempt
   */
  private _getNextReconnectionDelay(attempt: number): number {
    // Access default values directly, ensuring they're never undefined
    const initialDelay = this._reconnectionOptions.initialReconnectionDelay;
    const growFactor = this._reconnectionOptions.reconnectionDelayGrowFactor;
    const maxDelay = this._reconnectionOptions.maxReconnectionDelay;

    // Cap at maximum delay
    return Math.min(initialDelay * Math.pow(growFactor, attempt), maxDelay);

  }

  /**
   * Schedule a reconnection attempt with exponential backoff
   *
   * @param lastEventId The ID of the last received event for resumability
   * @param attemptCount Current reconnection attempt count for this specific stream
   */
  private _scheduleReconnection(options: { resumptionToken?: string, onresumptiontoken?: (token: string) => void, replayMessageId?: string | number }, attemptCount = 0): void {
    // Use provided options or default options
    const maxRetries = this._reconnectionOptions.maxRetries;

    // Check if we've exceeded maximum retry attempts
    if (maxRetries > 0 && attemptCount >= maxRetries) {
      this.onerror?.(new Error(`Maximum reconnection attempts (${maxRetries}) exceeded.`));
      return;
    }

    // Calculate next delay based on current attempt count
    const delay = this._getNextReconnectionDelay(attemptCount);

    // Schedule the reconnection
    setTimeout(() => {
      // Use the last event ID to resume where we left off
      this._startOrAuthSse(options).catch(error => {
        this.onerror?.(new Error(`Failed to reconnect SSE stream: ${error instanceof Error ? error.message : String(error)}`));
        // Schedule another attempt if this one failed, incrementing the attempt counter
        this._scheduleReconnection(options, attemptCount + 1);
      });
    }, delay);
  }

  private _handleSseStream(stream: ReadableStream<Uint8Array> | null, options: { onresumptiontoken?: (token: string) => void, replayMessageId?: string | number }): void {
    if (!stream) {
      return;
    }
    const { onresumptiontoken, replayMessageId } = options;

    let lastEventId: string | undefined;
    const processStream = async () => {
      // this is the closest we can get to trying to catch network errors
      // if something happens reader will throw
      try {
        // Create a pipeline: binary stream -> text decoder -> SSE parser
        const reader = stream
          .pipeThrough(new TextDecoderStream())
          .pipeThrough(new EventSourceParserStream())
          .getReader();


        while (true) {
          const { value: event, done } = await reader.read();
          if (done) {
            break;
          }

          // Update last event ID if provided
          if (event.id) {
            lastEventId = event.id;
            onresumptiontoken?.(event.id);
          }

          if (!event.event || event.event === "message") {
            try {
              const message = JSONRPCMessageSchema.parse(JSON.parse(event.data));
              if (replayMessageId !== undefined && isJSONRPCResponse(message)) {
                message.id = replayMessageId;
              }
              this.onmessage?.(message);
            } catch (error) {
              this.onerror?.(error as Error);
            }
          }
        }
      } catch (error) {
        // Handle stream errors - likely a network disconnect
        this.onerror?.(new Error(`SSE stream disconnected: ${error}`));

        // Attempt to reconnect if the stream disconnects unexpectedly and we aren't closing
        if (this._abortController && !this._abortController.signal.aborted) {
          // Use the exponential backoff reconnection strategy
          if (lastEventId !== undefined) {
            try {
              this._scheduleReconnection({
                resumptionToken: lastEventId,
                onresumptiontoken,
                replayMessageId
              }, 0);
            }
            catch (error) {
              this.onerror?.(new Error(`Failed to reconnect: ${error instanceof Error ? error.message : String(error)}`));

            }
          }
        }
      }
    };
    processStream();
  }

  async start() {
    if (this._abortController) {
      throw new Error(
        "StreamableHTTPClientTransport already started! If using Client class, note that connect() calls start() automatically.",
      );
    }

    this._abortController = new AbortController();
  }

  /**
   * Call this method after the user has finished authorizing via their user agent and is redirected back to the MCP client application. This will exchange the authorization code for an access token, enabling the next connection attempt to successfully auth.
   */
  /*async finishAuth(authorizationCode: string): Promise<void> {
    if (!this._authProvider) {
      throw new UnauthorizedError("No auth provider");
    }

    const result = await auth(this._authProvider, { serverUrl: this._url, authorizationCode, resourceMetadataUrl: this._resourceMetadataUrl });
    if (result !== "AUTHORIZED") {
      throw new UnauthorizedError("Failed to authorize");
    }
  }*/

  async close(): Promise<void> {
    // Abort any pending requests
    this._abortController?.abort();

    this.onclose?.();
  }

  async send(message: JSONRPCMessage | JSONRPCMessage[], options?: { resumptionToken?: string, onresumptiontoken?: (token: string) => void }): Promise<void> {
    try {
      const { resumptionToken, onresumptiontoken } = options || {};

      if (resumptionToken) {
        // If we have at last event ID, we need to reconnect the SSE stream
        this._startOrAuthSse({ resumptionToken, replayMessageId: isJSONRPCRequest(message) ? message.id : undefined }).catch(err => this.onerror?.(err));
        return;
      }

      const headers = await this._commonHeaders();
      headers.set("content-type", "application/json");
      headers.set("accept", "application/json, text/event-stream");

      const init = {
        ...this._requestInit,
        method: "POST",
        headers,
        body: JSON.stringify(message),
        signal: this._abortController?.signal,
      };

      const response = await this._fetchFn(this._url.toString(), init);

      // Handle session ID received during initialization
      const sessionId = response.headers.get("mcp-session-id");
      if (sessionId) {
        this._sessionId = sessionId;
      }

      if (!response.ok) {
        /*if (response.status === 401 && this._authProvider) {

          this._resourceMetadataUrl = extractResourceMetadataUrl(response);

          const result = await auth(this._authProvider, { serverUrl: this._url, resourceMetadataUrl: this._resourceMetadataUrl });
          if (result !== "AUTHORIZED") {
            throw new UnauthorizedError();
          }

          // Purposely _not_ awaited, so we don't call onerror twice
          return this.send(message);
        }*/

        const text = await response.text().catch(() => null);
        throw new Error(
          `Error POSTing to endpoint (HTTP ${response.status}): ${text}`,
        );
      }

      // If the response is 202 Accepted, there's no body to process
      if (response.status === 202) {
        // if the accepted notification is initialized, we start the SSE stream
        // if it's supported by the server
        if (isInitializedNotification(message)) {
          // Start without a lastEventId since this is a fresh connection
          this._startOrAuthSse({ resumptionToken: undefined }).catch(err => this.onerror?.(err));
        }
        return;
      }

      // Get original message(s) for detecting request IDs
      const messages = Array.isArray(message) ? message : [message];

      const hasRequests = messages.filter(msg => "method" in msg && "id" in msg && msg.id !== undefined).length > 0;

      // Check the response type
      const contentType = response.headers.get("content-type");

      if (hasRequests) {
        if (contentType?.includes("text/event-stream")) {
          // Handle SSE stream responses for requests
          // We use the same handler as standalone streams, which now supports
          // reconnection with the last event ID
          this._handleSseStream(response.body, { onresumptiontoken });
        } else if (contentType?.includes("application/json")) {
          // For non-streaming servers, we might get direct JSON responses
          const data = await response.json();
          const responseMessages = Array.isArray(data)
            ? data.map(msg => JSONRPCMessageSchema.parse(msg))
            : [JSONRPCMessageSchema.parse(data)];

          for (const msg of responseMessages) {
            this.onmessage?.(msg);
          }
        } else {
          throw new StreamableHTTPError(
            -1,
            `Unexpected content type: ${contentType}`,
          );
        }
      }
    } catch (error) {
      this.onerror?.(error as Error);
      throw error;
    }
  }

  get sessionId(): string | undefined {
    return this._sessionId;
  }

  /**
   * Terminates the current session by sending a DELETE request to the server.
   *
   * Clients that no longer need a particular session
   * (e.g., because the user is leaving the client application) SHOULD send an
   * HTTP DELETE to the MCP endpoint with the Mcp-Session-Id header to explicitly
   * terminate the session.
   *
   * The server MAY respond with HTTP 405 Method Not Allowed, indicating that
   * the server does not allow clients to terminate sessions.
   */
  async terminateSession(): Promise<void> {
    if (!this._sessionId) {
      return; // No session to terminate
    }

    try {
      const headers = await this._commonHeaders();

      const init = {
        ...this._requestInit,
        method: "DELETE",
        headers,
        signal: this._abortController?.signal,
      };

      const response = await this._fetchFn(this._url.toString(), init);

      // We specifically handle 405 as a valid response according to the spec,
      // meaning the server does not support explicit session termination
      if (!response.ok && response.status !== 405) {
        throw new StreamableHTTPError(
          response.status,
          `Failed to terminate session: ${response.statusText}`
        );
      }

      this._sessionId = undefined;
    } catch (error) {
      this.onerror?.(error as Error);
      throw error;
    }
  }
}


export function extractResourceMetadataUrl(res: Response): URL | undefined {

  const authenticateHeader = res.headers.get("WWW-Authenticate");
  if (!authenticateHeader) {
    return undefined;
  }

  const [type, scheme] = authenticateHeader.split(' ');
  if (type.toLowerCase() !== 'bearer' || !scheme) {
    console.log("Invalid WWW-Authenticate header format, expected 'Bearer'");
    return undefined;
  }
  const regex = /resource_metadata="([^"]*)"/;
  const match = regex.exec(authenticateHeader);

  if (!match) {
    return undefined;
  }

  try {
    return new URL(match[1]);
  } catch {
    console.log("Invalid resource metadata url: ", match[1]);
    return undefined;
  }
}