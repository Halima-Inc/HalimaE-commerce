import PaymentProjector from './payment.projector';

describe('PaymentProjector', () => {
    const mockRepo: any = {
        upsertRevenueSnapshot: jest.fn().mockResolvedValue(undefined),
        upsertCustomerCounter: jest.fn().mockResolvedValue(undefined),
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('updates revenue snapshot and customer counter on PaymentCaptured', async () => {
        const projector = new PaymentProjector(mockRepo);
        const event: any = {
            eventName: 'PaymentCaptured',
            eventId: 'pay-1',
            version: 1,
            occurredAt: new Date().toISOString(),
            aggregateId: 'ord-1',
            payload: { amount: 123.45, currency: 'USD', userId: 'user-42' },
        };

        await projector.consume(event);

        expect(mockRepo.upsertRevenueSnapshot).toHaveBeenCalledWith(
            expect.any(Date),
            123.45,
            1,
            0,
        );
        expect(mockRepo.upsertCustomerCounter).toHaveBeenCalledWith(
            'user-42',
            0,
            123.45,
        );
    });
});
