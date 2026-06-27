import { ApiProperty } from '@nestjs/swagger';
import { ResponseCategoryDto } from './response-category.dto';

export class ResponseCategoriesFilteredDto {
    @ApiProperty({
        description: 'Array of categories',
        type: [ResponseCategoryDto],
    })
    readonly categories: ResponseCategoryDto[];

    @ApiProperty({
        description: 'Pagination metadata',
        type: 'object',
        properties: {
            totalPages: {
                type: 'number',
                description: 'Total number of pages',
                example: 5,
            },
            currentPage: {
                type: 'number',
                description: 'Current page number',
                example: 1,
            },
            totalCategories: {
                type: 'number',
                description: 'Total number of categories',
                example: 25,
            },
        },
    })
    readonly meta: {
        readonly totalPages: number;
        readonly currentPage: number;
        readonly totalCategories: number;
    };
}
