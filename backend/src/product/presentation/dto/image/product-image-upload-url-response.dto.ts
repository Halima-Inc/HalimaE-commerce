import { ApiProperty } from '@nestjs/swagger';

export class ProductImageUploadUrlResponseDto {
    @ApiProperty({
        description: 'S3 object key to use later in finalize call',
        example:
            'products/123e4567-e89b-12d3-a456-426614174000/1712703287342-a2f7b9f8-0eb4-45ab-bb2e-80aa9f8c5f21.jpg',
    })
    readonly key!: string;

    @ApiProperty({
        description:
            'Pre-signed URL to upload the image directly to S3 via HTTP PUT',
    })
    readonly uploadUrl!: string;

    @ApiProperty({
        description: 'HTTP method expected by the signed upload URL',
        example: 'PUT',
    })
    readonly method!: 'PUT';

    @ApiProperty({
        description: 'Signed URL expiration time in seconds',
        example: 900,
    })
    readonly expiresIn!: number;
}
