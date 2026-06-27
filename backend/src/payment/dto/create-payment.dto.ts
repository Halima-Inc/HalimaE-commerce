import { PAYMENTMETHOD, PAYMENTSTATUS, Prisma } from '@prisma/client';

export interface createPaymentDto {
    readonly orderId: string;
    readonly provider: string;
    readonly providerRef: string;
    readonly amount: Prisma.Decimal;
    readonly currency: string;
    readonly status: PAYMENTSTATUS;
    readonly method: PAYMENTMETHOD;
    readonly billing_address?: BillingAddressDto;
}

export interface BillingAddressDto {
    readonly id: string;
    readonly firstName: string;
    readonly lastName: string;
    readonly email?: string;
    readonly phone: string;
    readonly line1: string;
    readonly line2?: string;
    readonly city: string;
    readonly country: string;
    readonly postalCode: string;
}
