/**
 * Amazon Bedrock Provider Implementation
 *
 * Routes requests through an API Gateway + Lambda proxy, so no AWS credentials
 * are needed in the plugin — just a plain API key.
 *
 * API key format: the value from API Gateway (e.g. "u8EcEAUoFl9iWdheTQhBN91NT6aLZji16EAZjKsH")
 * Endpoint: https://<api-id>.execute-api.us-east-1.amazonaws.com/prod/invoke
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
    description: 'Economy model via AWS Bedrock - Fast and cost-effective',
    tier: 'economy',
    contextWindow: 200000,
    maxOutputTokens: 8192,
    isDefault: false,
  },
];

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
}

// =============================================================================
// Provider Implementation
// =============================================================================

export class BedrockProvider implements LLMProvider {
  readonly name = 'Amazon Bedrock';
  readonly id = 'bedrock';
  readonly endpoint = 'https://bjirrau0gh.execute-api.us-east-1.amazonaws.com/prod/invoke';
  readonly keyPrefix = '';
  readonly keyPlaceholder = 'u8EcEAUoFl9iWdheTQhBN91NT6aLZji16EAZjKsH';
  readonly models: LLMModel[] = BEDROCK_MODELS;

  /**
   * Format request body for the Lambda proxy.
   * The proxy forwards prompt, model, maxTokens, and temperature to Bedrock.
   */
  formatRequest(config: RequestConfig): Record<string, unknown> {
    return {
      prompt: config.prompt.trim(),
      model: config.model,
      maxTokens: config.maxTokens,
      temperature: config.temperature,
      ...(config.additionalParams ?? {}),
    };
  }

  /**
   * Parse Bedrock's Claude response (returned as-is from the Lambda proxy).
   */
  parseResponse(response: unknown): LLMResponse {
    const bedrockResponse = response as BedrockClaudeResponse;

    if (!bedrockResponse.content || !Array.isArray(bedrockResponse.content)) {
      throw new LLMError(
        'Invalid response from Bedrock proxy: missing content array',
        LLMErrorCode.INVALID_REQUEST,
      );
    }

    const textContent = bedrockResponse.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');

    if (!textContent) {
      throw new LLMError(
        'Invalid response from Bedrock proxy: no text content found',
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
   * Validate that the API key is non-empty (API Gateway keys are 40 chars).
   */
  validateApiKey(apiKey: string): ApiKeyValidationResult {
    if (!apiKey || typeof apiKey !== 'string' || apiKey.trim().length === 0) {
      return {
        isValid: false,
        error: 'Bedrock API key required. Enter the API Gateway key from your AWS setup.',
      };
    }
    if (apiKey.trim().length < 20) {
      return {
        isValid: false,
        error: 'API key appears too short. Please check your API Gateway key.',
      };
    }
    return { isValid: true };
  }

  /**
   * Send the API Gateway key in the x-api-key header.
   */
  getHeaders(apiKey: string): RequestHeaders {
    return {
      'Content-Type': 'application/json',
      'x-api-key': apiKey.trim(),
    };
  }

  getDefaultModel(): LLMModel {
    return this.models.find((m) => m.isDefault) ?? this.models[1];
  }

  handleError(statusCode: number, response: unknown): LLMError {
    const errorResponse = response as BedrockErrorResponse | null;
    const errorMessage =
      errorResponse?.message ?? (typeof response === 'string' ? response : 'Unknown error');

    switch (statusCode) {
      case 400:
        return new LLMError(
          `Bedrock Error (400): ${errorMessage}`,
          LLMErrorCode.INVALID_REQUEST,
          400,
        );
      case 401:
      case 403:
        return new LLMError(
          `Bedrock Error (${statusCode}): Invalid API key or access denied.`,
          LLMErrorCode.INVALID_API_KEY,
          statusCode,
        );
      case 404:
        return new LLMError(
          'Bedrock Error (404): Model not found. Check the model ID is available in your region.',
          LLMErrorCode.MODEL_NOT_FOUND,
          404,
        );
      case 429:
        return new LLMError(
          'Bedrock Error (429): Too many requests. Please try again later.',
          LLMErrorCode.RATE_LIMIT_EXCEEDED,
          429,
        );
      case 500:
        return new LLMError(
          'Bedrock Error (500): Internal server error.',
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
