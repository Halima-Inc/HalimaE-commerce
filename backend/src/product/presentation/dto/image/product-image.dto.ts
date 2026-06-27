import { IsNumber, IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ProductImageDto {
    @ApiProperty({
        description: 'Alternative text for the image',
        example: 'Black cotton t-shirt front view',
        required: false,
    })
    @IsString()
    @IsOptional()
    public alt?: string;

    @ApiProperty({
        description: 'Sort order for displaying images',
        example: 1,
    })
    @IsNumber()
    public sort!: number;
}
