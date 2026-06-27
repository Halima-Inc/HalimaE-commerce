import { Injectable } from '@nestjs/common';
import { CreatePaymentIntentDto, SavePaymentDto } from './dto';
import {
    CreatePaymentIntentCommand,
    HandlePaymentWebhookCommand,
    RecordCashPaymentCommand,
    RefundPaymentCommand,
    SavePaymentCommand,
} from './application/commands';
import {
    CreatePaymentIntentHandler,
    HandlePaymentWebhookHandler,
    RecordCashPaymentHandler,
    RefundPaymentHandler,
    SavePaymentHandler,
} from './application/handlers';

@Injectable()
export class PaymentService {
    constructor(
        private readonly createPaymentIntentHandler: CreatePaymentIntentHandler,
        private readonly handlePaymentWebhookHandler: HandlePaymentWebhookHandler,
        private readonly savePaymentHandler: SavePaymentHandler,
        private readonly recordCashPaymentHandler: RecordCashPaymentHandler,
        private readonly refundPaymentHandler: RefundPaymentHandler,
    ) {}

    /**
     * Create payment intent and return payment URL
     * Returns null for cash on delivery
     */
    async createPaymentIntent(
        dto: CreatePaymentIntentDto,
    ): Promise<string | null> {
        return this.createPaymentIntentHandler.execute(
            new CreatePaymentIntentCommand(
                dto.orderId,
                dto.amount,
                dto.currency,
                dto.method,
                dto.billing_address,
            ),
        );
    }

    /**
     * Handle webhook from payment provider and save payment to database
     */
    async handleWebhook(
        payload: any,
        signature: string,
        headers: any,
    ): Promise<void> {
        return this.handlePaymentWebhookHandler.execute(
            new HandlePaymentWebhookCommand(payload, signature, headers),
        );
    }

    /**
     * Save payment to database with idempotency check
     */
    async savePayment(dto: SavePaymentDto): Promise<void> {
        await this.savePaymentHandler.execute(
            new SavePaymentCommand(
                dto.orderId,
                dto.provider,
                dto.providerRef,
                Number(dto.amount),
                dto.currency,
                dto.status,
                dto.method,
                dto.capturedAt,
            ),
        );
    }

    /**
     * Record cash payment (for admin/courier use)
     * Optimized: Only selects id field for validation
     */
    async recordCashPayment(
        orderId: string,
        amount: number,
        currency: string,
    ): Promise<void> {
        await this.recordCashPaymentHandler.execute(
            new RecordCashPaymentCommand(orderId, amount, currency),
        );
    }

    async refundPayment(paymentId: string, amount: number): Promise<boolean> {
        return this.refundPaymentHandler.execute(
            new RefundPaymentCommand(paymentId, amount),
        );
    }
}
