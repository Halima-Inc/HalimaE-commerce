import { PAYMENTMETHOD } from '@prisma/client';
import { BillingAddressDto } from '../../dto';

export class CreatePaymentIntentCommand {
    constructor(
        public readonly orderId: string,
        public readonly amount: number,
        public readonly currency: string,
        public readonly method: PAYMENTMETHOD,
        public readonly billingAddress?: BillingAddressDto,
    ) {}
}
