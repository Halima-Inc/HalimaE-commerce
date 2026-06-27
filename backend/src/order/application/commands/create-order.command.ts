import { CreateOrderDto } from '../../dto';

export class CreateOrderCommand {
    constructor(
        public readonly customerId: string,
        public readonly createOrderDto: CreateOrderDto,
    ) {}
}
