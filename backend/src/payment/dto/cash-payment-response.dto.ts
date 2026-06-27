import { ApiProperty } from '@nestjs/swagger';

export class CashPaymentResponseDto {
    @ApiProperty({
        description: 'Message about the payment recording',
        example: 'Cash payment recorded successfully',
    })
    message: string;
}
