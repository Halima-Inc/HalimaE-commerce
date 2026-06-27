import { UpdatePaymentStatusDto } from '../../dto';

export class UpdatePaymentStatusCommand {
    constructor(
        public readonly orderId: string,
        public readonly updateDto: UpdatePaymentStatusDto,
    ) {}
}
