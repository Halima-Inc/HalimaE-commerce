import { Decimal } from '@prisma/client/runtime/library';
import { ApiProperty } from '@nestjs/swagger';

class ProductImageDto {
    @ApiProperty({
        description: 'Image URL',
        example: 'https://example.com/images/product.jpg',
    })
    url: string;

    @ApiProperty({
        description: 'Alternative text',
        example: 'Product front view',
        required: false,
    })
    alt?: string;
}

class ProductInfoDto {
    @ApiProperty({
        description: 'Product ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    id: string;

    @ApiProperty({ description: 'Product name', example: 'Classic T-Shirt' })
    name: string;

    @ApiProperty({ description: 'Product slug', example: 'classic-t-shirt' })
    slug: string;

    @ApiProperty({ description: 'Product images', type: [ProductImageDto] })
    images: ProductImageDto[];
}

class VariantPriceInfoDto {
    @ApiProperty({
        description: 'Price ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    id: string;

    @ApiProperty({
        description: 'Price amount',
        example: 29.99,
        type: 'number',
    })
    amount: Decimal;

    @ApiProperty({ description: 'Currency code', example: 'EGP' })
    currency: string;

    @ApiProperty({
        description: 'Compare-at price',
        example: 39.99,
        type: 'number',
        required: false,
        nullable: true,
    })
    compareAt?: Decimal | null;
}

class VariantInfoDto {
    @ApiProperty({
        description: 'Variant ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    id: string;

    @ApiProperty({ description: 'SKU', example: 'TSH-BLK-M' })
    sku: string;

    @ApiProperty({ description: 'Size', example: 'M', required: false })
    size?: string;

    @ApiProperty({ description: 'Color', example: 'Black', required: false })
    color?: string;

    @ApiProperty({
        description: 'Material',
        example: 'Cotton',
        required: false,
    })
    material?: string;

    @ApiProperty({ description: 'Product information', type: ProductInfoDto })
    product: ProductInfoDto;

    @ApiProperty({ description: 'Variant prices', type: [VariantPriceInfoDto] })
    prices: VariantPriceInfoDto[];
}

export class CartItemResponseDto {
    @ApiProperty({
        description: 'Cart item ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    id: string;

    @ApiProperty({ description: 'Quantity', example: 2 })
    qty: number;

    @ApiProperty({
        description: 'Variant ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    variantId: string;

    @ApiProperty({ description: 'Variant information', type: VariantInfoDto })
    variant: VariantInfoDto;
}

export class CartResponseDto {
    @ApiProperty({
        description: 'Cart ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    id: string;

    @ApiProperty({
        description: 'Customer ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    customerId: string;

    @ApiProperty({
        description: 'Cart creation date',
        example: '2024-01-01T00:00:00.000Z',
    })
    createdAt: Date;

    @ApiProperty({
        description: 'Cart last update date',
        example: '2024-01-01T00:00:00.000Z',
    })
    updatedAt: Date;

    @ApiProperty({ description: 'Cart items', type: [CartItemResponseDto] })
    items: CartItemResponseDto[];

    @ApiProperty({ description: 'Total number of items in cart', example: 5 })
    totalItems: number;

    @ApiProperty({
        description: 'Estimated total price',
        example: 149.95,
        required: false,
    })
    estimatedTotal?: number;
}

class CheckoutVariantDto {
    @ApiProperty({
        description: 'Variant ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    id: string;

    @ApiProperty({ description: 'SKU', example: 'TSH-BLK-M' })
    sku: string;

    @ApiProperty({
        description: 'Product information',
        type: () => CheckoutProductDto,
    })
    product: { name: string };

    @ApiProperty({
        description: 'Variant prices',
        type: () => [CheckoutPriceDto],
    })
    prices: Array<{
        amount: Decimal;
        currency: string;
    }>;
}

class CheckoutProductDto {
    @ApiProperty({
        description: 'Product name for order snapshot',
        example: 'Classic T-Shirt',
    })
    name: string;
}

class CheckoutPriceDto {
    @ApiProperty({
        description: 'Price amount',
        example: 29.99,
        type: 'number',
    })
    amount: Decimal;

    @ApiProperty({ description: 'Currency code', example: 'EGP' })
    currency: string;
}

class CheckoutItemDto {
    @ApiProperty({
        description: 'Cart item ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    id: string;

    @ApiProperty({ description: 'Quantity', example: 2 })
    qty: number;

    @ApiProperty({
        description: 'Variant information',
        type: CheckoutVariantDto,
    })
    variant: CheckoutVariantDto;
}

// Lightweight checkout DTO - only essential data
export class CheckoutCartDto {
    @ApiProperty({
        description: 'Cart ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    id: string;

    @ApiProperty({
        description: 'Customer ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    customerId: string;

    @ApiProperty({
        description: 'Cart items for checkout',
        type: [CheckoutItemDto],
    })
    items: CheckoutItemDto[];

    @ApiProperty({ description: 'Total number of items', example: 5 })
    totalItems: number;
}
