import { IsNumber } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VariantInventoryDto {
    @ApiProperty({
        description: 'Available stock quantity',
        example: 100,
    })
    @IsNumber()
    public stockOnHand!: number;
}
