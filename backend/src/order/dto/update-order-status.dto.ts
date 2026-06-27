import { IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { ORDERSTATUS } from '@prisma/client';

export class UpdateOrderStatusDto {
    @ApiProperty({
        description: 'Order status',
        enum: ORDERSTATUS,
    })
    @IsEnum(ORDERSTATUS)
    status: ORDERSTATUS;
}
