import { IsOptional, IsEnum, IsString, IsInt, Min } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { FULFILLMENTSTATUS, ORDERSTATUS, PAYMENTSTATUS } from '@prisma/client';

export class FilterOrderDto {
    @ApiPropertyOptional({
        description: 'Order status filter',
        enum: ORDERSTATUS,
    })
    @IsOptional()
    @IsEnum(ORDERSTATUS)
    readonly status?: ORDERSTATUS;

    @ApiPropertyOptional({
        description: 'Payment status filter',
        enum: PAYMENTSTATUS,
    })
    @IsOptional()
    @IsEnum(PAYMENTSTATUS)
    readonly paymentStatus?: PAYMENTSTATUS;

    @ApiPropertyOptional({
        description: 'Fulfillment status filter',
        enum: FULFILLMENTSTATUS,
    })
    @IsOptional()
    @IsEnum(FULFILLMENTSTATUS)
    readonly fulfillmentStatus?: FULFILLMENTSTATUS;

    @ApiPropertyOptional({
        description: 'Page number',
        minimum: 1,
        default: 1,
    })
    @IsOptional()
    @Type(() => Number)
    @IsInt()
    @Min(1)
    readonly page?: number = 1;

    @ApiPropertyOptional({
        description: 'Items per page',
        minimum: 1,
        default: 10,
    })
    @IsOptional()
    @Type(() => Number)
    @IsInt()
    @Min(1)
    readonly limit?: number = 10;

    @ApiPropertyOptional({
        description: 'Search by order number',
        example: 'ORD-2025-001',
    })
    @IsOptional()
    @IsString()
    readonly orderNo?: string;

    @ApiPropertyOptional({
        description: 'Field to order by',
        example: 'createdAt',
    })
    @IsOptional()
    @IsString()
    readonly orderBy?: string;

    @ApiPropertyOptional({
        description: 'Sort order',
        example: 'asc',
    })
    @IsOptional()
    @IsEnum(['asc', 'desc'])
    readonly sortOrder?: 'asc' | 'desc';
}
