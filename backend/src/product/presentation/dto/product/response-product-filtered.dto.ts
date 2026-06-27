import { ApiProperty } from '@nestjs/swagger';
import { ResponseProductDto } from './response-product.dto';

class MetaDto {
    @ApiProperty({
        description: 'Total number of pages',
        example: 10,
    })
    readonly totalPages: number;

    @ApiProperty({
        description: 'Current page number',
        example: 1,
    })
    readonly currentPage: number;

    @ApiProperty({
        description: 'Total number of products matching the filter',
        example: 100,
    })
    readonly totalProducts: number;
}

export class ResponseProductFilteredDto {
    @ApiProperty({
        description: 'List of products',
        type: [ResponseProductDto],
    })
    readonly products: ResponseProductDto[];

    @ApiProperty({
        description: 'Pagination metadata',
        type: MetaDto,
    })
    readonly meta: MetaDto;
}
