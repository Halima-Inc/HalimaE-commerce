import { ApiProperty } from '@nestjs/swagger';
import { ResponseOrderDto } from './response-order.dto';

class MetaDto {
    @ApiProperty()
    total: number;

    @ApiProperty()
    page: number;

    @ApiProperty()
    limit: number;

    @ApiProperty()
    totalPages: number;
}

export class ResponseOrdersFilteredDto {
    @ApiProperty({ type: [ResponseOrderDto] })
    orders: ResponseOrderDto[];

    @ApiProperty()
    meta: MetaDto;
}
