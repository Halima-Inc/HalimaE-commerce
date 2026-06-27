import { Status } from '@prisma/client';
import { Type } from 'class-transformer';
import {
    IsDecimal,
    IsEnum,
    IsInt,
    IsNumber,
    IsOptional,
    IsString,
    Min,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class FilterProductDto {
    @ApiProperty({
        description: 'Filter by product name (partial match)',
        example: 'T-Shirt',
        required: false,
    })
    @IsOptional()
    @IsString()
    name?: string;

    @ApiProperty({
        description: 'Filter by category ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
        required: false,
    })
    @IsOptional()
    @IsString()
    categoryId?: string;

    @ApiProperty({
        description: 'Filter by product status',
        enum: Status,
        example: Status.ACTIVE,
        required: false,
    })
    @IsOptional()
    @IsEnum(Status)
    status?: Status;

    @ApiProperty({
        description: 'Page number for pagination',
        example: 1,
        default: 1,
        required: false,
    })
    @IsOptional()
    @Type(() => Number)
    @IsInt()
    @Min(1)
    page: number = 1;

    @ApiProperty({
        description: 'Minimum price filter',
        example: 0,
        default: 0,
        required: false,
    })
    @IsOptional()
    @Type(() => Number)
    @Min(0)
    priceMin: number = 0;

    @ApiProperty({
        description: 'Maximum price filter',
        example: 100,
        required: false,
    })
    @IsOptional()
    @Type(() => Number)
    priceMax?: number;
}
