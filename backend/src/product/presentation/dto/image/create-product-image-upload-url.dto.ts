import { ApiProperty } from '@nestjs/swagger';
import { IsIn, IsString } from 'class-validator';

const ALLOWED_CONTENT_TYPES = [
    'image/jpeg',
    'image/png',
    'image/webp',
] as const;

export class CreateProductImageUploadUrlDto {
    @ApiProperty({
        description: 'Image MIME type for the direct S3 upload',
        enum: ALLOWED_CONTENT_TYPES,
        example: 'image/jpeg',
    })
    @IsString()
    @IsIn(ALLOWED_CONTENT_TYPES)
    readonly contentType!: (typeof ALLOWED_CONTENT_TYPES)[number];
}
