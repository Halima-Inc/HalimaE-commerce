export class HandlePaymentWebhookCommand {
    constructor(
        public readonly payload: unknown,
        public readonly signature: string,
        public readonly headers: Record<string, unknown>,
    ) {}
}
