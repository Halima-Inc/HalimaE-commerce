import { PAYMENTMETHOD } from '@prisma/client';
import { BillingAddressDto, ParsedWebhookData } from '../dto';

export interface IPaymentProvider {
    readonly providerName: string;
    /**
     * Create a payment intent and return payment URL
     * Returns null for cash on delivery payments
     */
    createPaymentIntent(
        amount: number,
        currency: string,
        method: PAYMENTMETHOD,
        billing_data?: BillingAddressDto,
    ): Promise<string | null>;

    /**
     * Handle webhook from payment provider
     * Returns parsed webhook data or throws error if invalid
     */
    handleWebhook(
        payload: any,
        signature: string,
        headers: any,
    ): Promise<ParsedWebhookData>;

    /**
     * Refund a payment (not implemented yet)
     */
    refundPayment(paymentId: string, amount: number): Promise<boolean>;
}
