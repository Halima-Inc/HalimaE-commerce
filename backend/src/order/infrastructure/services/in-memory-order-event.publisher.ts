import { Injectable } from '@nestjs/common';
import { LogService } from '../../../common/log.service';
import type { OrderEvent } from '../../application/events';
import type { IOrderEventPublisher } from '../../application/services';

@Injectable()
export class InMemoryOrderEventPublisher implements IOrderEventPublisher {
    constructor(private readonly logger: LogService) {}

    async publish(event: OrderEvent): Promise<void> {
        this.logger.debug(
            `Order event published: ${event.eventName} (${event.eventId})`,
            InMemoryOrderEventPublisher.name,
        );
    }
}
