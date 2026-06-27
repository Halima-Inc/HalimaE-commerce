import { Inject, Injectable, BadRequestException } from '@nestjs/common';
import { createHmac } from 'crypto';
import { PAYMENTMETHOD, PAYMENTSTATUS } from '@prisma/client';
import { LogService } from '../../../common/log.service';
import type { IPaymentProvider } from '../../interfaces';
import type { IPaymentRepository } from '../../domain/interfaces';
import { PAYMENT_PROVIDER, PAYMENT_REPOSITORY } from '../../payment.tokens';
import { HandlePaymentWebhookCommand, SavePaymentCommand } from '../commands';
import { SavePaymentHandler } from './save-payment.handler';

@Injectable()
export class HandlePaymentWebhookHandler {
    constructor(
        @Inject(PAYMENT_PROVIDER)
        private readonly paymentProvider: IPaymentProvider,
        @Inject(PAYMENT_REPOSITORY)
        private readonly paymentRepository: IPaymentRepository,
        private readonly savePaymentHandler: SavePaymentHandler,
        private readonly logger: LogService,
    ) {}

    async execute(command: HandlePaymentWebhookCommand): Promise<void> {
        const payloadHash = this.hashPayload(command.payload);
        const signatureHash = this.hashPayload(command.signature);
        const provider = this.paymentProvider.providerName;

        const existingLog =
            await this.paymentRepository.findWebhookProcessingLog(
                provider,
                (
                    command.payload as { obj?: { id?: string | number } }
                )?.obj?.id?.toString() || 'unknown',
                signatureHash,
            );

        if (existingLog) {
            this.logger.debug(
                `Webhook already processed with status: ${existingLog.status}`,
                HandlePaymentWebhookHandler.name,
            );
            if (existingLog.status === 'SUCCESS') {
                return;
            }
            if (existingLog.status === 'FAILED') {
                throw new BadRequestException(
                    'Webhook processing previously failed; fix issue and retry',
                );
            }
        }

        const providerRef =
            (
                command.payload as { obj?: { id?: string | number } }
            )?.obj?.id?.toString() || 'unknown';

        await this.paymentRepository.createWebhookProcessingLog(
            provider,
            providerRef,
            payloadHash,
            signatureHash,
        );

        const webhookData = await this.paymentProvider.handleWebhook(
            command.payload,
            command.signature,
            command.headers,
        );

        try {
            this.logger.log(
                `Webhook received for order ${webhookData.orderId}, status: ${webhookData.status}`,
                HandlePaymentWebhookHandler.name,
            );

            await this.savePaymentHandler.execute(
                new SavePaymentCommand(
                    webhookData.orderId,
                    this.paymentProvider.providerName,
                    webhookData.transactionId,
                    webhookData.amount,
                    webhookData.currency,
                    webhookData.status as PAYMENTSTATUS,
                    webhookData.method as PAYMENTMETHOD,
                    webhookData.capturedAt,
                ),
            );

            await this.paymentRepository.markWebhookProcessingComplete(
                provider,
                providerRef,
                signatureHash,
            );

            this.logger.log(
                `Payment saved and webhook marked complete for order ${webhookData.orderId}`,
                HandlePaymentWebhookHandler.name,
            );
        } catch (error) {
            await this.paymentRepository.markWebhookProcessingFailed(
                provider,
                providerRef,
                signatureHash,
                error instanceof Error ? error.message : 'Unknown error',
            );

            throw error;
        }
    }

    private hashPayload(data: unknown): string {
        return createHmac('sha256', 'webhook-hash-key')
            .update(JSON.stringify(data))
            .digest('hex');
    }
}
