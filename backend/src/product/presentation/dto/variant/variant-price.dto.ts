import { Prisma } from '@prisma/client';
import { Type } from 'class-transformer';
import { IsDecimal, IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VariantPriceDto {
    @ApiProperty({
        description: 'Currency code (ISO 4217)',
        example: 'EGP',
    })
    @IsString()
    readonly currency: string;

    @ApiProperty({
        description: 'Price amount',
        example: 29.99,
        type: 'number',
    })
    @IsDecimal()
    readonly amount: Prisma.Decimal;

    @ApiProperty({
        description: 'Compare-at price (original price before discount)',
        example: 39.99,
        type: 'number',
        required: false,
        nullable: true,
    })
    @IsOptional()
    @IsDecimal()
    readonly compareAt?: Prisma.Decimal | null;
}
