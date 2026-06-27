import { ArgumentsHost, HttpException, HttpStatus } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { GlobalExceptionFilter } from './global-exception.filter';
import { CategoryHasChildrenException } from '../../category/domain/exceptions';
import { ProductNotFoundException } from '../../product/domain/exceptions';
import { InvalidCredentialsException } from '../../auth/domain/exceptions';

describe('GlobalExceptionFilter', () => {
    const logger = {
        error: jest.fn(),
    } as any;

    const createHost = () => {
        const response = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };

        const host = {
            switchToHttp: () => ({
                getResponse: () => response,
            }),
        } as ArgumentsHost;

        return { host, response };
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('uses the http status from a shared domain exception', () => {
        const filter = new GlobalExceptionFilter(logger);
        const { host, response } = createHost();

        filter.catch(new InvalidCredentialsException(), host);

        expect(response.status).toHaveBeenCalledWith(HttpStatus.UNAUTHORIZED);
        expect(response.json).toHaveBeenCalledWith(
            expect.objectContaining({
                success: false,
                error: {
                    message: 'Invalid credentials provided',
                    code: 'INVALID_CREDENTIALS',
                },
            }),
        );
    });

    it('handles category domain exceptions with their own status', () => {
        const filter = new GlobalExceptionFilter(logger);
        const { host, response } = createHost();

        filter.catch(new CategoryHasChildrenException(), host);

        expect(response.status).toHaveBeenCalledWith(HttpStatus.CONFLICT);
        expect(response.json).toHaveBeenCalledWith(
            expect.objectContaining({
                error: {
                    message: 'Cannot delete category with subcategories',
                    code: 'CATEGORY_HAS_CHILDREN',
                },
            }),
        );
    });

    it('keeps not found semantics for product domain exceptions', () => {
        const filter = new GlobalExceptionFilter(logger);
        const { host, response } = createHost();

        filter.catch(new ProductNotFoundException(), host);

        expect(response.status).toHaveBeenCalledWith(HttpStatus.NOT_FOUND);
        expect(response.json).toHaveBeenCalledWith(
            expect.objectContaining({
                error: {
                    message: 'Product not found',
                    code: 'PRODUCT_NOT_FOUND',
                },
            }),
        );
    });

    it('continues to pass through native HttpException status codes', () => {
        const filter = new GlobalExceptionFilter(logger);
        const { host, response } = createHost();

        filter.catch(
            new HttpException('Forbidden', HttpStatus.FORBIDDEN),
            host,
        );

        expect(response.status).toHaveBeenCalledWith(HttpStatus.FORBIDDEN);
    });

    it('continues to map Prisma validation errors to bad request', () => {
        const filter = new GlobalExceptionFilter(logger);
        const { host, response } = createHost();

        filter.catch(
            new Prisma.PrismaClientValidationError('Validation failed', {
                clientVersion: 'test',
            }),
            host,
        );

        expect(response.status).toHaveBeenCalledWith(HttpStatus.BAD_REQUEST);
    });
});
