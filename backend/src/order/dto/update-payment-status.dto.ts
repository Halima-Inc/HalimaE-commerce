import { IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { PAYMENTSTATUS } from '@prisma/client';

export class UpdatePaymentStatusDto {
    @ApiProperty({
        description: 'Payment status',
        enum: PAYMENTSTATUS,
    })
    @IsEnum(PAYMENTSTATUS)
    paymentStatus: PAYMENTSTATUS;
}
