import { UpdateFulfillmentStatusDto } from '../../dto';

export class UpdateFulfillmentStatusCommand {
    constructor(
        public readonly orderId: string,
        public readonly updateDto: UpdateFulfillmentStatusDto,
    ) {}
}
