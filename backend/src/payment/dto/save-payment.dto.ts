import { Prisma, PAYMENTMETHOD, PAYMENTSTATUS } from '@prisma/client';

/**
 * DTO for saving payment to database
 */
export class SavePaymentDto {
    readonly orderId: string;
    readonly provider: string;
    readonly providerRef: string;
    readonly amount: Prisma.Decimal;
    readonly currency: string;
    readonly status: PAYMENTSTATUS;
    readonly method: PAYMENTMETHOD;
    readonly capturedAt?: Date;
}
