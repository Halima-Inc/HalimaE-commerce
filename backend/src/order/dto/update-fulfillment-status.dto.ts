import { IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { FULFILLMENTSTATUS } from '@prisma/client';

export class UpdateFulfillmentStatusDto {
    @ApiProperty({
        description: 'Fulfillment status',
        enum: FULFILLMENTSTATUS,
    })
    @IsEnum(FULFILLMENTSTATUS)
    fulfillmentStatus: FULFILLMENTSTATUS;
}
