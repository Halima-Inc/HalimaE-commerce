import type { OrderEvent } from '../events';

export interface IOrderEventPublisher {
    publish(event: OrderEvent): Promise<void>;
}
