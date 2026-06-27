import { ApiProperty } from '@nestjs/swagger';
import { ProductVariantDto } from './product-variant.dto';

export class ResponseVariantDto extends ProductVariantDto {
    @ApiProperty({
        description: 'Variant ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    readonly id!: string;

    @ApiProperty({
        description:
            'Product ID this variant belongs to (optional when nested under product)',
        example: '123e4567-e89b-12d3-a456-426614174000',
        required: false,
    })
    readonly productId?: string;
}
