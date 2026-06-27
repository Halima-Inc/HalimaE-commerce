import { FilterOrderDto } from '../../dto';

export class GetAllOrdersQuery {
    constructor(public readonly filters: FilterOrderDto) {}
}
