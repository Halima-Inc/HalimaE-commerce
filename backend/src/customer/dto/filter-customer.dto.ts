import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsInt, Min, IsString, IsIn } from 'class-validator';
import { Transform, Type } from 'class-transformer';

export class FilterCustomerDto {
    @ApiPropertyOptional({
        description: 'Page number for pagination',
        example: 1,
        default: 1,
    })
    @IsOptional()
    @Type(() => Number)
    @IsInt()
    @Min(1)
    page?: number = 1;

    @ApiPropertyOptional({
        description: 'Number of items per page',
        example: 10,
        default: 10,
    })
    @IsOptional()
    @Type(() => Number)
    @IsInt()
    @Min(1)
    limit?: number = 10;

    @ApiPropertyOptional({
        description: 'Search term for filtering by name or email',
        example: 'john',
    })
    @IsOptional()
    @IsString()
    search?: string;

    @ApiPropertyOptional({
        description: 'Sort field',
        example: 'name',
        enum: ['name', 'email', 'createdAt', 'totalSpent', 'orderCount'],
        default: 'name',
    })
    @IsOptional()
    @IsString()
    @IsIn(['name', 'email', 'createdAt', 'totalSpent', 'orderCount'])
    sort?: 'name' | 'email' | 'createdAt' | 'totalSpent' | 'orderCount' = 'name';

    @ApiPropertyOptional({
        description: 'Sort order',
        example: 'asc',
        enum: ['asc', 'desc'],
        default: 'asc',
    })
    @IsOptional()
    @IsString()
    @IsIn(['asc', 'desc'])
    order?: 'asc' | 'desc' = 'asc';
}
