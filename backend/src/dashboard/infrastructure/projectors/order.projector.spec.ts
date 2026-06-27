import OrderProjector from './order.projector';

describe('OrderProjector', () => {
    const mockRepo: any = {
        upsertCustomerCounter: jest.fn().mockResolvedValue(undefined),
        upsertOrdersByStatus: jest.fn().mockResolvedValue(undefined),
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('updates customer counter and orders by status on OrderCreated', async () => {
        const projector = new OrderProjector(mockRepo);
        const event: any = {
            eventName: 'OrderCreated',
            eventId: 'evt-1',
            version: 1,
            occurredAt: new Date().toISOString(),
            aggregateId: 'ord-1',
            payload: { userId: 'user-1' },
        };

        await projector.consume(event);

        expect(mockRepo.upsertCustomerCounter).toHaveBeenCalledWith(
            'user-1',
            1,
            0,
        );
        expect(mockRepo.upsertOrdersByStatus).toHaveBeenCalledWith(
            'PENDING',
            expect.any(Date),
            1,
        );
    });

    it('updates orders by status on OrderStatusUpdated', async () => {
        const projector = new OrderProjector(mockRepo);
        const event: any = {
            eventName: 'OrderStatusUpdated',
            eventId: 'evt-2',
            version: 1,
            occurredAt: new Date().toISOString(),
            aggregateId: 'ord-1',
            payload: { status: 'SHIPPED' },
        };

        await projector.consume(event);

        expect(mockRepo.upsertOrdersByStatus).toHaveBeenCalledWith(
            'SHIPPED',
            expect.any(Date),
            1,
        );
    });
});
