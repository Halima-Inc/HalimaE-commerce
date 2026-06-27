import { ApiProperty, OmitType } from '@nestjs/swagger';
import { CreateProductDto } from './create-product.dto';
import { ResponseVariantDto } from '../variant/response-variant.dto';

class ProductImageResponseDto {
    @ApiProperty({
        description: 'Image ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    id: string;

    @ApiProperty({
        description: 'Product ID (optional when nested under product)',
        example: '123e4567-e89b-12d3-a456-426614174000',
        required: false,
    })
    productId?: string;

    @ApiProperty({
        description: 'Image URL',
        example: '/images/products/product-image.jpg',
    })
    url: string;

    @ApiProperty({
        description: 'Alternative text',
        example: 'Product front view',
        required: false,
        nullable: true,
    })
    alt?: string | null;

    @ApiProperty({
        description: 'Sort order (optional when not specified)',
        example: 1,
        required: false,
    })
    sort?: number;
}

export class ResponseProductDto extends OmitType(CreateProductDto, [
    'variants',
] as const) {
    @ApiProperty({
        description: 'Product ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    readonly id: string;

    @ApiProperty({
        description: 'Product variants with full details',
        type: [ResponseVariantDto],
    })
    readonly variants: ResponseVariantDto[];

    @ApiProperty({
        description: 'Product images',
        type: [ProductImageResponseDto],
    })
    readonly images: ProductImageResponseDto[];

    @ApiProperty({
        description: 'Product creation date',
        example: '2024-01-01T00:00:00.000Z',
    })
    readonly createdAt: Date;

    @ApiProperty({
        description: 'Product last update date',
        example: '2024-01-01T00:00:00.000Z',
    })
    readonly updatedAt: Date;
}
