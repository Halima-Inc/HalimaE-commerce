import type { PaymentEvent } from '../events';

export interface IPaymentEventPublisher {
    publish(event: PaymentEvent): Promise<void>;
}
