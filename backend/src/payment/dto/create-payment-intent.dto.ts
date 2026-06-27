import { PAYMENTMETHOD } from '@prisma/client';
import { BillingAddressDto } from './create-payment.dto';

/**
 * DTO for creating a payment intent (input from order service)
 */
export class CreatePaymentIntentDto {
    readonly orderId: string;
    readonly amount: number;
    readonly currency: string;
    readonly method: PAYMENTMETHOD;
    readonly billing_address?: BillingAddressDto;
}
