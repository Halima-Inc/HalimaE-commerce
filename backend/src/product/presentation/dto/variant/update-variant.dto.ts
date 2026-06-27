import { OmitType, PartialType, ApiProperty } from '@nestjs/swagger';
import { ProductVariantDto } from './product-variant.dto';
import { VariantPriceDto } from './variant-price.dto';
import { IsOptional, IsUUID } from 'class-validator';

export class UpdateVariantDto extends PartialType(
    OmitType(ProductVariantDto, ['prices'] as const),
) {
    @ApiProperty({
        description: 'Updated prices for the variant',
        type: () => [UpdateVariantPriceDto],
        required: false,
    })
    @IsOptional()
    readonly prices?: UpdateVariantPriceDto[];
}

export class UpdateVariantPriceDto extends PartialType(VariantPriceDto) {
    @ApiProperty({
        description: 'Price ID for updating existing price',
        example: '123e4567-e89b-12d3-a456-426614174000',
        required: false,
    })
    @IsOptional()
    @IsUUID()
    id: string;
}
