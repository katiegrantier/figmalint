/**
 * Amazon Bedrock Provider Implementation
 *
 * Implements the LLMProvider interface for AWS Bedrock's Claude models.
 * Uses SigV4 request signing for authentication — no API key required,
 * only AWS credentials.
 *
 * Credential format (single field):
 *   "ACCESS_KEY_ID:SECRET_ACCESS_KEY"
 *   "ACCESS_KEY_ID:SECRET_ACCESS_KEY:REGION"
 *   "ACCESS_KEY_ID:SECRET_ACCESS_KEY:REGION:SESSION_TOKEN"
 *
 * Default region: us-east-1
 */

import {
  LLMProvider,
  LLMModel,
  RequestConfig,
  LLMResponse,
  ApiKeyValidationResult,
  RequestHeaders,
  LLMError,
  LLMErrorCode,
} from './types';

const DEFAULT_REGION = 'us-east-1';
const BEDROCK_SERVICE = 'bedrock-runtime';

// =============================================================================
// Model Definitions
// =============================================================================

export const BEDROCK_MODELS: LLMModel[] = [
  {
    id: 'anthropic.claude-3-opus-20240229',
    name: 'Claude 3 Opus (Bedrock)',
    description: 'Flagship model via AWS Bedrock - Most capable for complex design analysis',
    tier: 'flagship',
    contextWindow: 200000,
    maxOutputTokens: 4096,
    isDefault: false,
  },
  {
    id: 'anthropic.claude-3-5-sonnet-20241022',
    name: 'Claude 3.5 Sonnet (Bedrock)',
    description: 'Standard model via AWS Bedrock - Balanced performance and cost',
    tier: 'standard',
    contextWindow: 200000,
    maxOutputTokens: 8192,
    isDefault: true,
  },
  {
    id: 'anthropic.claude-3-5-haiku-20241022',
    name: 'Claude 3.5 Haiku (Bedrock)',
    description: 'Economy model via AWS Bedrock - Fast responses, cost-effective',
    tier: 'economy',
    contextWindow: 200000,
    maxOutputTokens: 8192,
    isDefault: false,
  },
];

// =============================================================================
// Credential Parsing
// =============================================================================

export interface BedrockCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  sessionToken?: string;
}

/**
 * Parse combined credential string into individual fields.
 * Format: "ACCESS_KEY_ID:SECRET_ACCESS_KEY[:REGION[:SESSION_TOKEN]]"
 */
export function parseBedrockCredentials(credential: string): BedrockCredentials {
  const parts = credential.trim().split(':');
  return {
    accessKeyId: parts[0] ?? '',
    secretAccessKey: parts[1] ?? '',
    region: parts[2] ?? DEFAULT_REGION,
    sessionToken: parts[3],
  };
}

// =============================================================================
// SigV4 Signing Utilities
// =============================================================================

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function sha256Hex(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const hash = await crypto.subtle.digest('SHA-256', encoded);
  return toHex(hash);
}

async function hmacSha256(key: ArrayBuffer, data: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
}

/**
 * Compute SigV4-signed headers for a Bedrock POST request.
 *
 * @returns Headers object ready to pass to fetch(), including Authorization.
 */
export async function computeBedrockHeaders(
  endpoint: string,
  body: string,
  credentials: BedrockCredentials,
): Promise<Record<string, string>> {
  const { accessKeyId, secretAccessKey, region, sessionToken } = credentials;

  const now = new Date();
  // YYYYMMDDTHHMMSSZ
  const amzDate = now.toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  // YYYYMMDD
  const dateStamp = amzDate.slice(0, 8);

  const urlObj = new URL(endpoint);
  const host = urlObj.host;
  const canonicalUri = urlObj.pathname;

  // Hash the payload
  const payloadHash = await sha256Hex(body);

  // Build canonical headers (must be sorted and lowercase)
  const canonicalHeadersList: Array<[string, string]> = [
    ['content-type', 'application/json'],
    ['host', host],
    ['x-amz-date', amzDate],
  ];
  if (sessionToken) {
    canonicalHeadersList.push(['x-amz-security-token', sessionToken]);
  }
  canonicalHeadersList.sort((a, b) => a[0].localeCompare(b[0]));

  const canonicalHeaders = canonicalHeadersList.map(([k, v]) => `${k}:${v}`).join('\n') + '\n';
  const signedHeaders = canonicalHeadersList.map(([k]) => k).join(';');

  // Canonical request
  const canonicalRequest = [
    'POST',
    canonicalUri,
    '', // no query string
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  // Credential scope
  const credentialScope = `${dateStamp}/${region}/${BEDROCK_SERVICE}/aws4_request`;

  // String to sign
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join('\n');

  // Derive signing key
  const encoder = new TextEncoder();
  const kDate = await hmacSha256(encoder.encode(`AWS4${secretAccessKey}`), dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, BEDROCK_SERVICE);
  const kSigning = await hmacSha256(kService, 'aws4_request');

  // Compute signature
  const signature = toHex(await hmacSha256(kSigning, stringToSign));

  // Build Authorization header
  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-amz-date': amzDate,
    Authorization: authorization,
  };

  if (sessionToken) {
    headers['x-amz-security-token'] = sessionToken;
  }

  return headers;
}

// =============================================================================
// Response Types
// =============================================================================

interface BedrockClaudeResponse {
  id: string;
  type: string;
  role: string;
  content: Array<{ type: string; text: string }>;
  model: string;
  stop_reason: string;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
}

interface BedrockErrorResponse {
  message?: string;
  __type?: string;
}

// =============================================================================
// Provider Implementation
// =============================================================================

export class BedrockProvider implements LLMProvider {
  readonly name = 'Amazon Bedrock';
  readonly id = 'bedrock';
  // Endpoint is dynamic per-model; this is used as the base for display only
  readonly endpoint = 'https://bedrock-runtime.amazonaws.com';
  // AWS access keys start with AKIA (long-term) or ASIA (temporary)
  readonly keyPrefix = 'AKIA';
  readonly keyPlaceholder = 'AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY:us-east-1';
  readonly models: LLMModel[] = BEDROCK_MODELS;

  /**
   * Format a request body for Bedrock's Claude InvokeModel API.
   * Note: model ID is NOT included in the body — it's part of the URL.
   */
  formatRequest(config: RequestConfig): Record<string, unknown> {
    const request: Record<string, unknown> = {
      anthropic_version: 'bedrock-2023-05-31',
      messages: [
        {
          role: 'user',
          content: config.prompt.trim(),
        },
      ],
      max_tokens: config.maxTokens,
      temperature: config.temperature,
    };

    if (config.additionalParams) {
      Object.assign(request, config.additionalParams);
    }

    return request;
  }

  /**
   * Parse Bedrock's Claude response into the standardized LLMResponse format.
   */
  parseResponse(response: unknown): LLMResponse {
    const bedrockResponse = response as BedrockClaudeResponse;

    if (!bedrockResponse.content || !Array.isArray(bedrockResponse.content)) {
      throw new LLMError(
        'Invalid response from Bedrock: missing content array',
        LLMErrorCode.INVALID_REQUEST,
      );
    }

    const textContent = bedrockResponse.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');

    if (!textContent) {
      throw new LLMError(
        'Invalid response from Bedrock: no text content found',
        LLMErrorCode.INVALID_REQUEST,
      );
    }

    return {
      content: textContent.trim(),
      model: bedrockResponse.model,
      usage: bedrockResponse.usage
        ? {
            promptTokens: bedrockResponse.usage.input_tokens,
            completionTokens: bedrockResponse.usage.output_tokens,
            totalTokens: bedrockResponse.usage.input_tokens + bedrockResponse.usage.output_tokens,
          }
        : undefined,
      metadata: {
        id: bedrockResponse.id,
        stopReason: bedrockResponse.stop_reason,
      },
    };
  }

  /**
   * Validate that the credential string has at least ACCESS_KEY_ID:SECRET_ACCESS_KEY.
   */
  validateApiKey(apiKey: string): ApiKeyValidationResult {
    if (!apiKey || typeof apiKey !== 'string') {
      return {
        isValid: false,
        error: 'Credentials required. Use format: ACCESS_KEY_ID:SECRET_ACCESS_KEY[:REGION]',
      };
    }

    const trimmed = apiKey.trim();
    const parts = trimmed.split(':');

    if (parts.length < 2 || !parts[0] || !parts[1]) {
      return {
        isValid: false,
        error:
          'Invalid credential format. Expected: ACCESS_KEY_ID:SECRET_ACCESS_KEY or ACCESS_KEY_ID:SECRET_ACCESS_KEY:REGION',
      };
    }

    const accessKeyId = parts[0];
    if (accessKeyId.length < 16 || accessKeyId.length > 128) {
      return {
        isValid: false,
        error: 'Invalid AWS Access Key ID. Please check your credentials.',
      };
    }

    const secretAccessKey = parts[1];
    if (secretAccessKey.length < 1) {
      return {
        isValid: false,
        error: 'AWS Secret Access Key cannot be empty.',
      };
    }

    return { isValid: true };
  }

  /**
   * Returns basic content-type header only.
   * SigV4 Authorization is computed asynchronously in callProvider (index.ts).
   */
  getHeaders(_apiKey: string): RequestHeaders {
    return {
      'content-type': 'application/json',
    };
  }

  getDefaultModel(): LLMModel {
    return this.models.find((m) => m.isDefault) ?? this.models[1];
  }

  handleError(statusCode: number, response: unknown): LLMError {
    const errorResponse = response as BedrockErrorResponse | null;
    const errorMessage =
      errorResponse?.message || (typeof response === 'string' ? response : 'Unknown error');

    switch (statusCode) {
      case 400:
        return new LLMError(
          `Bedrock Error (400): ${errorMessage}. Check your request format.`,
          LLMErrorCode.INVALID_REQUEST,
          400,
        );

      case 401:
      case 403:
        return new LLMError(
          `Bedrock Error (${statusCode}): Access denied. Check your AWS credentials and IAM permissions.`,
          LLMErrorCode.INVALID_API_KEY,
          statusCode,
        );

      case 404:
        return new LLMError(
          `Bedrock Error (404): Model not found. Verify the model ID is available in your region.`,
          LLMErrorCode.MODEL_NOT_FOUND,
          404,
        );

      case 429:
        return new LLMError(
          'Bedrock Error (429): Throttled. Please try again later.',
          LLMErrorCode.RATE_LIMIT_EXCEEDED,
          429,
        );

      case 500:
        return new LLMError(
          'Bedrock Error (500): Internal server error. Please try again.',
          LLMErrorCode.SERVER_ERROR,
          500,
        );

      case 503:
        return new LLMError(
          'Bedrock Error (503): Service unavailable. Please try again later.',
          LLMErrorCode.SERVICE_UNAVAILABLE,
          503,
        );

      default:
        return new LLMError(
          `Bedrock Error (${statusCode}): ${errorMessage}`,
          LLMErrorCode.UNKNOWN_ERROR,
          statusCode,
        );
    }
  }
}

export const bedrockProvider = new BedrockProvider();
export default bedrockProvider;
