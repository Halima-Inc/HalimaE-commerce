import {
    IsArray,
    IsEnum,
    IsOptional,
    IsString,
    ValidateNested,
} from 'class-validator';
import { Transform, Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { ProductImageDto } from '../image/product-image.dto';
import { ProductVariantDto } from '../variant/product-variant.dto';
import { Status } from '@prisma/client';

export class CreateProductDto {
    @ApiProperty({
        description: 'Product name',
        example: 'Classic Cotton T-Shirt',
    })
    @IsString()
    public name!: string;

    @ApiProperty({
        description: 'Product description',
        example: 'Comfortable cotton t-shirt perfect for everyday wear',
        required: false,
        nullable: true,
    })
    @IsString()
    @IsOptional()
    public description?: string | null;

    @ApiProperty({
        description: 'URL-friendly product identifier',
        example: 'classic-cotton-t-shirt',
    })
    @IsString()
    public slug!: string;

    @ApiProperty({
        description: 'Product status',
        enum: Status,
        example: Status.ACTIVE,
    })
    @IsEnum(Status)
    public status!: Status;

    @ApiProperty({
        description: 'Category ID the product belongs to',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @IsString()
    public categoryId!: string;

    @ApiProperty({
        description: 'Product variants (sizes, colors, etc.)',
        type: () => [ProductVariantDto],
        example: [
            {
                sku: 'TSH-BLK-M',
                size: 'M',
                color: 'Black',
                material: 'Cotton',
                isActive: true,
                prices: [
                    {
                        currency: 'EGP',
                        amount: 29.99,
                        compareAt: 39.99,
                    },
                ],
                inventory: {
                    stockOnHand: 100,
                },
            },
        ],
    })
    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => ProductVariantDto)
    @Transform(({ value }) =>
        typeof value === 'string' ? JSON.parse(value) : value,
    )
    public variants!: ProductVariantDto[];
}
