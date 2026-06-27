import { ApiResponse, ErrorResponseDto } from '../src/common/dto/response.dto';

/**
 * Utility functions for testing standardized API responses
 */

/**
 * Validates that a response follows the standardized success format
 */
export function expectSuccessResponse<T>(
    response: any,
    expectedStatusCode: number = 200,
): T {
    // Validate the response structure
    expect(response.body).toHaveProperty('success', true);
    expect(response.body).toHaveProperty('data');
    expect(response.body).toHaveProperty('message');
    expect(response.body).toHaveProperty('statusCode', expectedStatusCode);
    expect(response.body).toHaveProperty('timestamp');
    expect(response.body.error).toBeNull();

    // Validate timestamp format
    expect(new Date(response.body.timestamp).getTime()).not.toBeNaN();

    // Return the actual data for further testing
    return response.body.data;
}

/**
 * Validates that a response follows the standardized error format
 */
export function expectErrorResponse(
    response: any,
    expectedStatusCode: number,
): ErrorResponseDto {
    // Validate the response structure
    expect(response.body).toHaveProperty('success', false);
    expect(response.body).toHaveProperty('data', null);
    expect(response.body).toHaveProperty('error');
    expect(response.body.error).not.toBeNull();
    expect(response.body).toHaveProperty('statusCode', expectedStatusCode);
    expect(response.body).toHaveProperty('timestamp');

    // Validate error object structure
    const error = response.body.error;
    expect(error).toHaveProperty('message');
    // code is optional
    expect(error).not.toHaveProperty('statusCode');
    expect(error).not.toHaveProperty('timestamp');
    expect(error).not.toHaveProperty('path');

    // Validate timestamp format at root
    expect(new Date(response.body.timestamp).getTime()).not.toBeNaN();

    return error;
}

/**
 * Creates a matcher for success responses with specific data expectations
 */
export function expectSuccessResponseWithData<T>(
    expectedData: Partial<T>,
    statusCode: number = 200,
) {
    return (response: any) => {
        const data = expectSuccessResponse<T>(response, statusCode);
        expect(data).toMatchObject(expectedData);
        return data;
    };
}

/**
 * Creates a matcher for error responses with specific message expectations
 */
export function expectErrorResponseWithMessage(
    expectedMessage: string | RegExp,
    statusCode: number,
) {
    return (response: any) => {
        const error = expectErrorResponse(response, statusCode);
        if (typeof expectedMessage === 'string') {
            expect(error.message).toBe(expectedMessage);
        } else {
            expect(error.message).toMatch(expectedMessage);
        }
        return error;
    };
}

/**
 * Validates that a response is a successful array response
 */
export function expectSuccessArrayResponse<T>(
    response: any,
    expectedStatusCode: number = 200,
): T[] {
    const data = expectSuccessResponse<T[]>(response, expectedStatusCode);
    expect(Array.isArray(data)).toBe(true);
    return data;
}

/**
 * Validates that a response is a successful paginated response
 */
export function expectSuccessPaginatedResponse<T>(
    response: any,
    expectedStatusCode: number = 200,
): { items: T[]; meta: any } {
    const data = expectSuccessResponse<any>(response, expectedStatusCode);

    // For paginated responses, the data structure varies
    // Some might have { products: [], meta: {} }, others might have { items: [], meta: {} }
    // We'll be flexible here
    expect(data).toHaveProperty('meta');
    expect(data.meta).toHaveProperty('totalPages');
    expect(data.meta).toHaveProperty('currentPage');

    return data;
}

/**
 * Helper to extract auth token from login response
 */
export function extractAuthTokenFromResponse(response: any): string {
    // For login responses, we might get 200 or 201 status
    const data = expectSuccessResponse<any>(response, response.status);
    const token = data.accessToken ?? data.access_token;
    expect(token).toBeDefined();
    return token;
}

/**
 * Validates HTTP status without checking response body (for cases like 204 No Content)
 */
export function expectHttpStatus(response: any, expectedStatusCode: number) {
    expect(response.status).toBe(expectedStatusCode);
}

/**
 * Validates that the response has the correct message for different HTTP methods
 */
export function expectSuccessMessage(
    response: any,
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
) {
    const expectedMessages = {
        GET: 'Request completed successfully',
        POST: 'Resource created successfully',
        PUT: 'Resource updated successfully',
        PATCH: 'Resource updated successfully',
        DELETE: 'Resource deleted successfully',
    };

    expect(response.body.message).toBe(expectedMessages[method]);
}
