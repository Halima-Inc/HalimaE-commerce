import type { OrderEvent } from '../../../order/application/events';

export interface IDashboardOrderEventConsumer {
    consume(event: OrderEvent): Promise<void>;
}
