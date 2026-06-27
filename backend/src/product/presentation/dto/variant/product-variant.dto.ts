import {
    IsArray,
    IsBoolean,
    IsOptional,
    IsString,
    ValidateNested,
} from 'class-validator';
import { Transform, Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { VariantPriceDto } from './variant-price.dto';
import { VariantInventoryDto } from './variant-inventory.dto';

export class ProductVariantDto {
    @ApiProperty({
        description: 'Stock Keeping Unit identifier',
        example: 'TSH-BLK-M',
        required: false,
    })
    @IsString()
    @IsOptional()
    readonly sku!: string;

    @ApiProperty({
        description: 'Product size',
        example: 'M',
        required: false,
        nullable: true,
    })
    @IsString()
    @IsOptional()
    readonly size?: string | null;

    @ApiProperty({
        description: 'Product color',
        example: 'Black',
        required: false,
        nullable: true,
    })
    @IsString()
    @IsOptional()
    readonly color?: string | null;

    @ApiProperty({
        description: 'Product material',
        example: 'Cotton',
        required: false,
        nullable: true,
    })
    @IsString()
    @IsOptional()
    readonly material?: string | null;

    @ApiProperty({
        description: 'Whether this variant is active for sale',
        example: true,
        default: true,
        required: false,
        nullable: true,
    })
    @IsBoolean()
    @IsOptional()
    readonly isActive?: boolean | null = true;

    @ApiProperty({
        description: 'Variant pricing in different currencies',
        type: () => [VariantPriceDto],
        example: [
            {
                currency: 'EGP',
                amount: 29.99,
                compareAt: 39.99,
            },
        ],
    })
    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => VariantPriceDto)
    readonly prices!: VariantPriceDto[];

    @ApiProperty({
        description: 'Inventory information for this variant (required)',
        type: () => VariantInventoryDto,
        example: {
            stockOnHand: 100,
        },
    })
    @ValidateNested()
    @Type(() => VariantInventoryDto)
    readonly inventory!: VariantInventoryDto;
}
