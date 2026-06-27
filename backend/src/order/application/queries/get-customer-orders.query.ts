import { FilterOrderDto } from '../../dto';

export class GetCustomerOrdersQuery {
    constructor(
        public readonly customerId: string,
        public readonly filters: FilterOrderDto,
    ) {}
}
