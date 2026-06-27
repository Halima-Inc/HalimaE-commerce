import { ApiProperty, ApiPropertyOptional, OmitType } from '@nestjs/swagger';
import { CreateCategoryDto } from './create-category.dto';

export class ResponseCategoryDto extends OmitType(CreateCategoryDto, [
    'parentId',
] as const) {
    @ApiProperty({
        description: 'Unique identifier of the category',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    readonly id: string;

    @ApiPropertyOptional({
        description: 'Parent category information (null for root categories)',
        type: () => ResponseCategoryDto,
        nullable: true,
    })
    readonly parent?: ResponseCategoryDto | null;
}
