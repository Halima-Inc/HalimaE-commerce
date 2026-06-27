export class GetOrderByOrderNoQuery {
    constructor(
        public readonly orderNo: string,
        public readonly customerId?: string,
    ) {}
}
