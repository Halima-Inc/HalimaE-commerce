import { UpdateOrderStatusDto } from '../../dto';

export class UpdateOrderStatusCommand {
    constructor(
        public readonly orderId: string,
        public readonly updateDto: UpdateOrderStatusDto,
    ) {}
}
