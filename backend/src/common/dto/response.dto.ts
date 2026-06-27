export class ErrorResponseDto {
    message!: string | string[];
    code?: string | number;
}

export class ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: ErrorResponseDto | null;
    message?: string;
    statusCode?: number;
    timestamp?: string;

    constructor(
        success: boolean,
        data?: T,
        error: ErrorResponseDto | null = null,
        message?: string,
    ) {
        this.success = success;
        this.data = data;
        this.error = error;
        this.message = message;
        this.timestamp = new Date().toISOString();
    }

    static success<T>(data: T, message?: string): ApiResponse<T> {
        return new ApiResponse(true, data, null, message);
    }

    static error(error: ErrorResponseDto): ApiResponse<null> {
        return new ApiResponse(false, null, error);
    }
}
