import type { PaymentEvent } from '../../../payment/application/events';

export interface IDashboardPaymentEventConsumer {
    consume(event: PaymentEvent): Promise<void>;
}
