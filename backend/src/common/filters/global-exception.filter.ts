import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpException,
    HttpStatus,
    Injectable,
    type LoggerService,
} from '@nestjs/common';
import { Response } from 'express';
import { ApiResponse, ErrorResponseDto } from '../dto/response.dto';
import { Prisma } from '@prisma/client';
import { DomainException } from '../exceptions';

@Injectable()
@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
    constructor(private readonly logger: LoggerService) {}

    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<Response>();

        let httpStatus: number;
        let errorResponse: ErrorResponseDto;

        if (exception instanceof HttpException) {
            httpStatus = exception.getStatus();
            const exceptionResponse = exception.getResponse();

            if (typeof exceptionResponse === 'string') {
                errorResponse = {
                    message: exceptionResponse,
                };
            } else {
                errorResponse = {
                    message:
                        (exceptionResponse as any).message || exception.message,
                    code: (exceptionResponse as any).code,
                };
            }
        } else if (exception instanceof Prisma.PrismaClientKnownRequestError) {
            const prismaError = exception;
            httpStatus = this.getPrismaErrorStatus(prismaError.code);
            errorResponse = {
                message: this.getPrismaErrorMessage(prismaError),
                code: prismaError.code,
            };
        } else if (exception instanceof Prisma.PrismaClientValidationError) {
            httpStatus = HttpStatus.BAD_REQUEST;
            errorResponse = {
                message: 'Invalid data provided',
                code: 'VALIDATION_ERROR',
            };
            this.logger.debug?.(
                `Validation error: ${exception.message}`,
                GlobalExceptionFilter.name,
            );
        } else if (exception instanceof DomainException) {
            httpStatus = exception.httpStatus;
            errorResponse = {
                message: exception.message,
                code: exception.code,
            };
        } else {
            httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
            errorResponse = {
                message: 'Internal server error',
            };

            this.logger.error(
                `Unexpected error: ${String(exception)}`,
                exception instanceof Error ? exception.stack : undefined,
                GlobalExceptionFilter.name,
            );
        }

        const apiResponse = ApiResponse.error(errorResponse);
        apiResponse.statusCode = httpStatus;

        response.status(httpStatus).json(apiResponse);
    }

    private getPrismaErrorStatus(code: string): number {
        switch (code) {
            case 'P2002':
                return HttpStatus.CONFLICT;
            case 'P2025':
                return HttpStatus.NOT_FOUND;
            case 'P2003':
                return HttpStatus.BAD_REQUEST;
            case 'P2014':
                return HttpStatus.BAD_REQUEST;
            default:
                return HttpStatus.INTERNAL_SERVER_ERROR;
        }
    }

    private getPrismaErrorMessage(
        exception: Prisma.PrismaClientKnownRequestError,
    ): string {
        switch (exception.code) {
            case 'P2002':
                return `Duplicate entry. ${this.extractFieldFromMeta(exception.meta)} already exists.`;
            case 'P2025':
                return 'Record not found or you do not have permission to access it.';
            case 'P2003':
                return 'Invalid reference. Related record does not exist.';
            case 'P2014':
                return 'Invalid ID provided.';
            default:
                return 'Database operation failed.';
        }
    }

    private extractFieldFromMeta(meta: any): string {
        if (meta?.target) {
            if (Array.isArray(meta.target)) {
                return meta.target.join(', ');
            }
            return meta.target;
        }
        return 'Field';
    }
}
