import { IsNumber, IsPositive, IsString, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RecordCashPaymentDto {
    @ApiProperty({
        description: 'Payment amount',
        example: 499.99,
        minimum: 0.01,
    })
    @IsNumber()
    @IsPositive()
    amount: number;

    @ApiProperty({
        description: 'Currency code (ISO 4217)',
        example: 'EGP',
        minLength: 3,
        maxLength: 3,
    })
    @IsString()
    @Length(3, 3)
    currency: string;
}
