import { IsString, IsUUID, IsEnum, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { PAYMENTMETHOD } from '@prisma/client';

export class CreateOrderDto {
    @ApiProperty({
        description: 'Billing address ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @IsUUID()
    readonly billingAddressId: string;

    @ApiProperty({
        description: 'Shipping address ID',
        example: '123e4567-e89b-12d3-a456-426614174001',
    })
    @IsUUID()
    readonly shippingAddressId: string;

    @ApiProperty({
        description: 'Currency code (defaults to EGP)',
        example: 'EGP',
        default: 'EGP',
    })
    @IsOptional()
    @IsString()
    readonly currency: string;

    @ApiProperty({
        description: 'Payment method to use',
        example: 'CARD',
        enum: PAYMENTMETHOD,
    })
    @IsEnum(PAYMENTMETHOD)
    readonly paymentMethod: PAYMENTMETHOD;
}
