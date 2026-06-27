export class RecordCashPaymentCommand {
    constructor(
        public readonly orderId: string,
        public readonly amount: number,
        public readonly currency: string,
    ) {}
}
