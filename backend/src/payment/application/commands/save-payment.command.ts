import { PAYMENTMETHOD, PAYMENTSTATUS } from '@prisma/client';

export class SavePaymentCommand {
    constructor(
        public readonly orderId: string,
        public readonly provider: string,
        public readonly providerRef: string,
        public readonly amount: number,
        public readonly currency: string,
        public readonly status: PAYMENTSTATUS,
        public readonly method: PAYMENTMETHOD,
        public readonly capturedAt?: Date,
    ) {}
}
