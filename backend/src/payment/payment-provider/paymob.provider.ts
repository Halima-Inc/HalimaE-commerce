import {
    BadGatewayException,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { catchError, lastValueFrom, retry } from 'rxjs';
import { createHmac, timingSafeEqual } from 'crypto';
import { PAYMENTMETHOD } from '@prisma/client';
import { BillingAddressDto, ParsedWebhookData } from '../dto';
import { LogService } from '../../common/log.service';
import { IPaymentProvider } from '../interfaces';

@Injectable()
export class PaymobProvider implements IPaymentProvider {
    public readonly providerName = 'PAYMOB';

    private readonly base_url: string;
    private readonly api_key: string;
    private readonly iframe_id: number;
    private readonly card_integeration_id: number;
    private readonly wallet_integeration_id: number;

    constructor(
        private readonly configService: ConfigService,
        private readonly httpService: HttpService,
        private readonly logger: LogService,
    ) {
        this.base_url = this.configService.get<string>('PAYMOB_BASE_URL')!;
        this.api_key = this.configService.get<string>('PAYMOB_API_KEY')!;
        this.iframe_id = this.configService.get<number>('PAYMOB_IFRAME_ID')!;
        this.card_integeration_id = this.configService.get<number>(
            'PAYMOB_CARD_INTEGRATION_ID',
        )!;
        this.wallet_integeration_id = this.configService.get<number>(
            'PAYMOB_WALLET_INTEGRATION_ID',
        )!;
    }

    async createPaymentIntent(
        amount: number,
        currency: string,
        method: PAYMENTMETHOD,
        billing_data?: BillingAddressDto,
    ): Promise<string | null> {
        try {
            const authToken = await this.authenticate();
            const paymobOrderId = await this.createOrder(
                authToken,
                amount,
                currency,
                [],
            );

            if (method === PAYMENTMETHOD.CARD) {
                const paymentKey = await this.generatePaymentKey(
                    authToken,
                    paymobOrderId,
                    amount,
                    currency,
                    billing_data,
                );

                return `${this.base_url}/acceptance/iframes/${this.iframe_id}?payment_token=${paymentKey}`;
            }

            if (method === PAYMENTMETHOD.WALLET) {
                return this.createWalletPayment(
                    authToken,
                    paymobOrderId,
                    amount,
                    currency,
                    billing_data,
                );
            }

            if (method === PAYMENTMETHOD.CASH_ON_DELIVERY) {
                return null;
            }

            throw new Error(`Unsupported payment method: ${String(method)}`);
        } catch (error: unknown) {
            throw new Error(
                `Failed to create payment intent: ${getErrorMessage(error)}`,
            );
        }
    }

    async handleWebhook(
        payload: any,
        signature: string,
        headers: any,
    ): Promise<ParsedWebhookData> {
        void headers;

        try {
            const calculatedHmac = createHmac('sha512', this.api_key)
                .update(JSON.stringify(payload))
                .digest('hex');

            this.validateSignature(calculatedHmac, signature);

            const obj = payload?.obj;
            if (!obj) {
                throw new Error('Invalid webhook payload: missing obj');
            }

            const status: ParsedWebhookData['status'] =
                obj.success && !obj.pending ? 'PAID' : 'FAILED';

            let method: ParsedWebhookData['method'] = 'CARD';
            const sourceType = obj.source_data?.type?.toLowerCase();
            const sourceSubType =
                obj.source_data?.sub_type?.toLowerCase() || '';

            if (
                sourceType === 'wallet' ||
                sourceSubType.includes('wallet') ||
                sourceSubType.includes('cash')
            ) {
                method = 'WALLET';
            }

            const orderId =
                obj.order?.merchant_order_id || String(obj.order?.id);

            return {
                orderId,
                transactionId: String(obj.id),
                amount: obj.amount_cents / 100,
                currency: obj.currency,
                status,
                method,
                capturedAt: new Date(obj.created_at),
            };
        } catch (error: unknown) {
            throw new Error(
                `Failed to parse webhook: ${getErrorMessage(error)}`,
            );
        }
    }

    refundPayment(paymentId: string, amount: number): Promise<boolean> {
        void paymentId;
        void amount;
        throw new Error('Method not implemented.');
    }

    private validateSignature(calculatedHmac: string, signature: string): void {
        const provided = Buffer.from(signature || '', 'utf8');
        const calculated = Buffer.from(calculatedHmac, 'utf8');

        if (
            provided.length !== calculated.length ||
            !timingSafeEqual(provided, calculated)
        ) {
            throw new UnauthorizedException('Invalid webhook signature');
        }
    }

    private async authenticate(): Promise<string> {
        const authRes = await lastValueFrom(
            this.httpService
                .post(`${this.base_url}/auth/tokens`, {
                    api_key: this.api_key,
                })
                .pipe(
                    retry(3),
                    catchError((error: unknown) => {
                        const message = getErrorMessage(error);
                        this.logger.error(
                            `Failed to authenticate with Paymob: ${message}`,
                            error instanceof Error ? error.stack : undefined,
                            PaymobProvider.name,
                        );
                        throw new BadGatewayException(
                            'Failed to authenticate with Paymob',
                        );
                    }),
                ),
        );

        return authRes.data.token;
    }

    private async createOrder(
        authToken: string,
        amount: number,
        currency: string,
        items: any[],
    ): Promise<string> {
        const orderRes = await lastValueFrom(
            this.httpService
                .post(`${this.base_url}/ecommerce/orders`, {
                    auth_token: authToken,
                    delivery_needed: false,
                    amount_cents: amount * 100,
                    currency,
                    items: items || [],
                })
                .pipe(
                    retry(3),
                    catchError((error: unknown) => {
                        const message = getErrorMessage(error);
                        this.logger.error(
                            `Failed to create order: ${message}`,
                            error instanceof Error ? error.stack : undefined,
                            PaymobProvider.name,
                        );
                        throw new BadGatewayException(
                            'Failed to create payment order',
                        );
                    }),
                ),
        );

        return String(orderRes.data.id);
    }

    private transformBillingData(billing_data?: BillingAddressDto) {
        if (!billing_data) {
            return {
                first_name: 'NA',
                last_name: 'NA',
                email: 'NA',
                phone_number: 'NA',
                apartment: 'NA',
                floor: 'NA',
                street: 'NA',
                building: 'NA',
                shipping_method: 'NA',
                postal_code: 'NA',
                city: 'NA',
                country: 'NA',
                state: 'NA',
            };
        }

        return {
            first_name: billing_data.firstName,
            last_name: billing_data.lastName,
            email: billing_data.email || 'NA',
            phone_number: billing_data.phone,
            apartment: billing_data.line2 || 'NA',
            floor: 'NA',
            street: billing_data.line1,
            building: 'NA',
            shipping_method: 'NA',
            postal_code: billing_data.postalCode,
            city: billing_data.city,
            country: billing_data.country,
            state: 'NA',
        };
    }

    private async generatePaymentKey(
        authToken: string,
        paymobOrderId: string,
        amount: number,
        currency: string,
        billing_data?: BillingAddressDto,
    ): Promise<string> {
        const paymentKeyRes = await lastValueFrom(
            this.httpService
                .post(`${this.base_url}/acceptance/payment_keys`, {
                    auth_token: authToken,
                    amount_cents: amount * 100,
                    expiration: 3600,
                    order_id: paymobOrderId,
                    billing_data: this.transformBillingData(billing_data),
                    currency,
                    integration_id: this.card_integeration_id,
                    lock_order_when_paid: 'false',
                })
                .pipe(
                    retry(3),
                    catchError((error: unknown) => {
                        const message = getErrorMessage(error);
                        this.logger.error(
                            `Failed to generate payment key: ${message}`,
                            error instanceof Error ? error.stack : undefined,
                            PaymobProvider.name,
                        );
                        throw new BadGatewayException(
                            'Failed to generate payment key',
                        );
                    }),
                ),
        );

        return paymentKeyRes.data.token;
    }

    private async createWalletPayment(
        authToken: string,
        paymobOrderId: string,
        amount: number,
        currency: string,
        billing_data?: BillingAddressDto,
    ): Promise<string> {
        const walletRes = await lastValueFrom(
            this.httpService
                .post(`${this.base_url}/acceptance/payments/pay`, {
                    source: {
                        identifier: billing_data?.phone,
                        subtype: 'WALLET',
                    },
                    payment_token: await this.generateWalletToken(
                        authToken,
                        paymobOrderId,
                        amount,
                        currency,
                        billing_data,
                    ),
                })
                .pipe(
                    retry(3),
                    catchError((error: unknown) => {
                        const message = getErrorMessage(error);
                        this.logger.error(
                            `Failed to create wallet payment: ${message}`,
                            error instanceof Error ? error.stack : undefined,
                            PaymobProvider.name,
                        );
                        throw new BadGatewayException(
                            'Failed to create wallet payment',
                        );
                    }),
                ),
        );

        return walletRes.data.redirect_url;
    }

    private async generateWalletToken(
        authToken: string,
        paymobOrderId: string,
        amount: number,
        currency: string,
        billing_data?: BillingAddressDto,
    ): Promise<string> {
        const tokenRes = await lastValueFrom(
            this.httpService
                .post(`${this.base_url}/acceptance/payment_keys`, {
                    auth_token: authToken,
                    amount_cents: amount * 100,
                    expiration: 3600,
                    order_id: paymobOrderId,
                    billing_data: this.transformBillingData(billing_data),
                    currency,
                    integration_id: this.wallet_integeration_id,
                    lock_order_when_paid: 'false',
                })
                .pipe(
                    retry(3),
                    catchError((error: unknown) => {
                        const message = getErrorMessage(error);
                        this.logger.error(
                            `Failed to generate wallet payment key: ${message}`,
                            error instanceof Error ? error.stack : undefined,
                            PaymobProvider.name,
                        );
                        throw new BadGatewayException(
                            'Failed to generate wallet payment key',
                        );
                    }),
                ),
        );

        return tokenRes.data.token;
    }
}

function getErrorMessage(error: unknown): string {
    if (error instanceof Error) {
        return error.message;
    }

    return 'Unknown error';
}
