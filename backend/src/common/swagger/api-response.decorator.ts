import { applyDecorators, Type } from '@nestjs/common';
import { ApiResponse, getSchemaPath } from '@nestjs/swagger';

export function ApiStandardResponse<TModel extends Type<any>>(
    model: TModel,
    description = 'Success',
    status = 200,
    customMessage?: string,
) {
    return applyDecorators(
        ApiResponse({
            status,
            description,
            schema: {
                type: 'object',
                properties: {
                    success: {
                        type: 'boolean',
                        example: true,
                        description:
                            'Indicates if the operation was successful',
                    },
                    data: {
                        $ref: getSchemaPath(model),
                        description: 'The response data',
                    },
                    error: {
                        type: 'null',
                        example: null,
                        description:
                            'Error details (null for successful responses)',
                    },
                    message: {
                        type: 'string',
                        example:
                            customMessage || 'Request completed successfully',
                        description:
                            'A human-readable message about the operation',
                    },
                    statusCode: {
                        type: 'number',
                        example: status,
                        description: 'HTTP status code',
                    },
                    timestamp: {
                        type: 'string',
                        format: 'date-time',
                        example: new Date().toISOString(),
                        description: 'Timestamp of the response (ISO 8601)',
                    },
                },
                required: [
                    'success',
                    'data',
                    'error',
                    'message',
                    'statusCode',
                    'timestamp',
                ],
            },
        }),
    );
}

export function ApiStandardErrorResponse(
    status: number,
    description: string,
    exampleMessage?: string,
    errorCode?: string,
) {
    const message = exampleMessage || description;
    const code = errorCode;

    return applyDecorators(
        ApiResponse({
            status,
            description,
            schema: {
                type: 'object',
                properties: {
                    success: {
                        type: 'boolean',
                        example: false,
                        description:
                            'Indicates if the operation was successful',
                    },
                    data: {
                        type: 'null',
                        example: null,
                        description: 'No data returned for error responses',
                    },
                    error: {
                        type: 'object',
                        description: 'Error details',
                        properties: {
                            message: {
                                oneOf: [
                                    { type: 'string' },
                                    {
                                        type: 'array',
                                        items: { type: 'string' },
                                    },
                                ],
                                example: message,
                                description:
                                    'Error message or array of validation errors',
                            },
                            ...(code
                                ? {
                                      code: {
                                          type: 'string',
                                          example: code,
                                          description:
                                              'Optional error code for client-side handling',
                                      },
                                  }
                                : {}),
                        },
                        required: ['message'],
                    },
                    statusCode: {
                        type: 'number',
                        example: status,
                        description: 'HTTP status code',
                    },
                    timestamp: {
                        type: 'string',
                        format: 'date-time',
                        example: new Date().toISOString(),
                        description: 'Timestamp of the response (ISO 8601)',
                    },
                },
                required: [
                    'success',
                    'data',
                    'error',
                    'statusCode',
                    'timestamp',
                ],
            },
        }),
    );
}

export function ApiStandardNoContentResponse(
    description = 'Resource deleted successfully',
) {
    return applyDecorators(
        ApiResponse({
            status: 204,
            description,
            schema: {
                type: 'object',
                properties: {
                    success: {
                        type: 'boolean',
                        example: true,
                        description:
                            'Indicates if the operation was successful',
                    },
                    data: {
                        type: 'null',
                        example: null,
                        description: 'No data returned for delete operations',
                    },
                    error: {
                        type: 'null',
                        example: null,
                        description:
                            'Error details (null for successful responses)',
                    },
                    message: {
                        type: 'string',
                        example: description,
                        description:
                            'A human-readable message about the operation',
                    },
                    statusCode: {
                        type: 'number',
                        example: 204,
                        description: 'HTTP status code',
                    },
                    timestamp: {
                        type: 'string',
                        format: 'date-time',
                        example: new Date().toISOString(),
                        description: 'Timestamp of the response (ISO 8601)',
                    },
                },
                required: [
                    'success',
                    'data',
                    'error',
                    'message',
                    'statusCode',
                    'timestamp',
                ],
            },
        }),
    );
}
