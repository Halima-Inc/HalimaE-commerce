import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNumber, IsOptional, IsString, Min } from 'class-validator';

export class FinalizeProductImageUploadDto {
    @ApiProperty({
        description: 'S3 object key returned from the signed URL endpoint',
        example:
            'products/123e4567-e89b-12d3-a456-426614174000/1712703287342-a2f7b9f8-0eb4-45ab-bb2e-80aa9f8c5f21.jpg',
    })
    @IsString()
    readonly key!: string;

    @ApiPropertyOptional({
        description: 'Alternative text for the image',
        example: 'Front angle shot',
    })
    @IsOptional()
    @IsString()
    readonly alt?: string;

    @ApiPropertyOptional({
        description: 'Sort order for displaying images',
        example: 1,
        minimum: 0,
    })
    @IsOptional()
    @IsNumber()
    @Min(0)
    readonly sort?: number;
}
