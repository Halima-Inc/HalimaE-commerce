import { IsOptional, IsString, Length, ValidateIf } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateCategoryDto {
    @ApiProperty({
        description: 'The name of the category',
        example: 'Electronics',
        minLength: 3,
        maxLength: 255,
    })
    @IsString()
    @Length(3, 255)
    readonly name: string;

    @ApiProperty({
        description: 'The URL-friendly slug for the category',
        example: 'electronics',
        minLength: 3,
        maxLength: 255,
    })
    @IsString()
    @Length(3, 255)
    readonly slug: string;

    @ApiPropertyOptional({
        description: 'The ID of the parent category (null for root categories)',
        example: '123e4567-e89b-12d3-a456-426614174000',
        nullable: true,
    })
    @IsOptional()
    @ValidateIf((obj, value) => value !== null)
    @IsString()
    readonly parentId?: string | null;
}
