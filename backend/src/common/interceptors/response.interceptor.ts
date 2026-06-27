import {
    Injectable,
    NestInterceptor,
    ExecutionContext,
    CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ApiResponse } from '../dto/response.dto';
import { Reflector } from '@nestjs/core';

@Injectable()
export class ResponseInterceptor<T>
    implements NestInterceptor<T, ApiResponse<T>>
{
    constructor(private reflector: Reflector) {}

    intercept(
        context: ExecutionContext,
        next: CallHandler,
    ): Observable<ApiResponse<T>> {
        const request = context.switchToHttp().getRequest();
        const response = context.switchToHttp().getResponse();

        return next.handle().pipe(
            map((data) => {
                if (data && typeof data === 'object' && 'success' in data) {
                    return data;
                }

                const statusCode = response.statusCode;
                let message: string | undefined;

                if (statusCode >= 200 && statusCode < 300) {
                    const method = request.method;
                    switch (method) {
                        case 'POST':
                            message = 'Resource created successfully';
                            break;
                        case 'PUT':
                        case 'PATCH':
                            message = 'Resource updated successfully';
                            break;
                        case 'DELETE':
                            message = 'Resource deleted successfully';
                            break;
                        case 'GET':
                        default:
                            message = 'Request completed successfully';
                            break;
                    }
                }

                const apiResponse = ApiResponse.success(data, message);
                apiResponse.statusCode = statusCode;

                return apiResponse;
            }),
        );
    }
}
