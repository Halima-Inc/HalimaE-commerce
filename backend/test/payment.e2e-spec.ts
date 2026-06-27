import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import {
    setupE2ETest,
    teardownE2ETest,
    getUniqueTestData,
} from './jest-e2e.setup';
import * as argon2 from 'argon2';
import { PrismaService } from '../src/prisma/prisma.service';
import { PAYMENTMETHOD, PAYMENTSTATUS, Status } from '@prisma/client';
import {
    expectSuccessResponse,
    expectErrorResponse,
    extractAuthTokenFromResponse,
} from './test-utils';
import * as crypto from 'crypto';
import { OutboxDispatcherScheduler } from '../src/payment/infrastructure/schedulers/outbox-dispatcher.scheduler';
import { OrderOutboxDispatcherScheduler } from '../src/order/infrastructure/schedulers/order-outbox-dispatcher.scheduler';

describe('PaymentController (e2e)', () => {
    let app: INestApplication;
    let prisma: PrismaService;
    let customerToken: string;
    let customerId: string;
    let adminToken: string;
    let orderId: string;
    let testData: any;

    async function dispatchOutboxEvents() {
        try {
            const paymentDispatcher = app.get(OutboxDispatcherScheduler);
            await paymentDispatcher.dispatchPendingEvents();
        } catch (e) {
            console.error('Error dispatching payment outbox events:', e);
        }

        try {
            const orderDispatcher = app.get(OrderOutboxDispatcherScheduler);
            await orderDispatcher.dispatchPendingEvents();
        } catch (e) {
            console.error('Error dispatching order outbox events:', e);
        }
    }

    // Mock Paymob webhook payload
    const createMockPaymobWebhook = (
        orderId: string,
        success: boolean = true,
    ) => ({
        obj: {
            id: Math.floor(Math.random() * 1000000),
            pending: false,
            success,
            amount_cents: 20000, // 200 EGP
            currency: 'EGP',
            created_at: new Date().toISOString(),
            order: {
                merchant_order_id: orderId,
                id: Math.floor(Math.random() * 1000000),
            },
            source_data: {
                type: 'card',
                sub_type: 'MasterCard',
            },
        },
    });

    // Helper to generate HMAC signature (for webhook simulation)
    const generateWebhookSignature = (payload: any, apiKey: string): string => {
        return crypto
            .createHmac('sha512', apiKey)
            .update(JSON.stringify(payload))
            .digest('hex');
    };

    // Helper to reset inventory for tests
    const resetInventory = async () => {
        const variant = await prisma.productVariant.findFirst();
        if (variant) {
            await prisma.variantInventory.updateMany({
                where: { variantId: variant.id },
                data: { stockOnHand: 1000 }, // Set high stock for tests
            });
        }
    };

    beforeAll(async () => {
        ({ app, prisma } = await setupE2ETest());
        testData = getUniqueTestData('payment');

        // Find or create customer role
        let role = await prisma.role.findFirst({
            where: { name: 'customer' },
        });
        if (!role) {
            role = await prisma.role.create({
                data: { name: 'customer' },
            });
        }
        const customerRoleId = role.id;

        // Create test customer
        const customer = await prisma.user.create({
            data: {
                name: testData.name,
                email: testData.email,
                passwordHash: await argon2.hash('password123'),
                phone: '1234567890',
                status: Status.ACTIVE,
                roleId: customerRoleId,
            },
        });
        customerId = customer.id;

        // Login customer
        const customerLoginResponse = await request(app.getHttpServer())
            .post('/api/auth/login')
            .send({ email: testData.email, password: 'password123' });

        customerToken = extractAuthTokenFromResponse(customerLoginResponse);

        // Create admin user
        const adminData = getUniqueTestData('admin');
        let adminRole = await prisma.role.findFirst({
            where: { name: 'admin' },
        });
        if (!adminRole) {
            adminRole = await prisma.role.create({
                data: { name: 'admin' },
            });
        }

        await prisma.user.create({
            data: {
                name: adminData.name,
                email: adminData.email,
                passwordHash: await argon2.hash('admin123'),
                roleId: adminRole.id,
            },
        });

        // Login admin
        const adminLoginResponse = await request(app.getHttpServer())
            .post('/api/auth/login')
            .send({ email: adminData.email, password: 'admin123' });

        adminToken = extractAuthTokenFromResponse(adminLoginResponse);

        // Create test order for payment testing
        const categoryData = getUniqueTestData('category');
        const category = await prisma.category.create({
            data: {
                name: categoryData.name,
                slug: categoryData.slug,
            },
        });

        const productData = getUniqueTestData('product');
        const product = await prisma.product.create({
            data: {
                name: productData.name,
                slug: productData.slug,
                description: 'Test product for payment',
                status: Status.ACTIVE,
                categoryId: category.id,
            },
        });

        const variantData = getUniqueTestData('variant');
        const variant = await prisma.productVariant.create({
            data: {
                productId: product.id,
                sku: variantData.sku,
                size: 'M',
                color: 'Blue',
                isActive: true,
            },
        });

        await prisma.variantPrice.create({
            data: {
                variantId: variant.id,
                currency: 'EGP',
                amount: 100.0,
            },
        });

        await prisma.variantInventory.create({
            data: {
                variantId: variant.id,
                stockOnHand: 1000, // High stock for all tests
            },
        });

        // Create addresses
        const billingAddress = await prisma.address.create({
            data: {
                userId: customerId,
                firstName: 'John',
                lastName: 'Doe',
                phone: '1234567890',
                line1: '123 Test St',
                city: 'Cairo',
                country: 'Egypt',
                postalCode: '12345',
            },
        });

        const shippingAddress = await prisma.address.create({
            data: {
                userId: customerId,
                firstName: 'John',
                lastName: 'Doe',
                phone: '1234567890',
                line1: '456 Test Ave',
                city: 'Cairo',
                country: 'Egypt',
                postalCode: '12345',
            },
        });

        // Create cart and order
        const cart = await prisma.cart.create({
            data: { customerId },
        });

        await prisma.cartItem.create({
            data: {
                cartId: cart.id,
                variantId: variant.id,
                qty: 2,
            },
        });

        const orderResponse = await request(app.getHttpServer())
            .post('/api/orders/checkout')
            .set('Authorization', `Bearer ${customerToken}`)
            .send({
                billingAddressId: billingAddress.id,
                shippingAddressId: shippingAddress.id,
                currency: 'EGP',
                paymentMethod: PAYMENTMETHOD.CARD,
            });

        const order = expectSuccessResponse<any>(orderResponse, 201);
        orderId = order.id;
    }, 30000);

    afterAll(async () => {
        await teardownE2ETest(app, prisma);
    });

    describe('POST /payment/webhook (Paymob Webhook)', () => {
        it('should process successful card payment webhook', async () => {
            const webhookPayload = createMockPaymobWebhook(orderId, true);
            const signature = generateWebhookSignature(
                webhookPayload,
                process.env.PAYMOB_API_KEY || 'test-key',
            );

            const response = await request(app.getHttpServer())
                .post('/api/payment/webhook')
                .set('x-paymob-signature', signature)
                .send(webhookPayload);

            expect(response.status).toBe(200);
            expect(response.body).toHaveProperty('success', true);
            expect(response.body).toHaveProperty('message');

            // Verify payment was saved
            const payment = await prisma.payment.findFirst({
                where: { orderId },
            });

            expect(payment).toBeDefined();
            expect(payment?.status).toBe(PAYMENTSTATUS.PAID);
            expect(payment?.method).toBe(PAYMENTMETHOD.CARD);
            expect(Number(payment?.amount)).toBe(200);

            // Verify order payment status was updated
            await dispatchOutboxEvents();
            const order = await prisma.order.findUnique({
                where: { id: orderId },
            });

            expect(order?.paymentStatus).toBe(PAYMENTSTATUS.PAID);
        });

        it('should process failed payment webhook', async () => {
            // Reset inventory
            await resetInventory();

            // Create another order for failed payment test
            await prisma.cartItem.deleteMany({
                where: { cart: { customerId } },
            });
            await prisma.cart.deleteMany({ where: { customerId } });

            const cart = await prisma.cart.create({
                data: { customerId },
            });

            const variant = await prisma.productVariant.findFirst();
            await prisma.cartItem.create({
                data: {
                    cartId: cart.id,
                    variantId: variant!.id,
                    qty: 1,
                },
            });

            const billingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
            });
            const shippingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
                skip: 1,
            });

            const orderResponse = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddress!.id,
                    shippingAddressId: shippingAddress!.id,
                    currency: 'EGP',
                    paymentMethod: PAYMENTMETHOD.CARD,
                });

            const failedOrder = expectSuccessResponse<any>(orderResponse, 201);
            const failedOrderId = failedOrder.id;

            const webhookPayload = createMockPaymobWebhook(
                failedOrderId,
                false,
            );
            const signature = generateWebhookSignature(
                webhookPayload,
                process.env.PAYMOB_API_KEY || 'test-key',
            );

            const response = await request(app.getHttpServer())
                .post('/api/payment/webhook')
                .set('x-paymob-signature', signature)
                .send(webhookPayload);

            expect(response.status).toBe(200);

            // Verify payment was saved with FAILED status
            const payment = await prisma.payment.findFirst({
                where: { orderId: failedOrderId },
            });

            expect(payment).toBeDefined();
            expect(payment?.status).toBe(PAYMENTSTATUS.FAILED);
        });

        it('should prevent duplicate webhook processing (idempotency)', async () => {
            const webhookPayload = createMockPaymobWebhook(orderId, true);
            const signature = generateWebhookSignature(
                webhookPayload,
                process.env.PAYMOB_API_KEY || 'test-key',
            );

            // First webhook
            const response1 = await request(app.getHttpServer())
                .post('/api/payment/webhook')
                .set('x-paymob-signature', signature)
                .send(webhookPayload);

            expect(response1.status).toBe(200);

            // Count payments before duplicate
            const paymentsBefore = await prisma.payment.count({
                where: { orderId },
            });

            // Duplicate webhook (same transactionId)
            const response2 = await request(app.getHttpServer())
                .post('/api/payment/webhook')
                .set('x-paymob-signature', signature)
                .send(webhookPayload);

            expect(response2.status).toBe(200);

            // Count payments after duplicate - should be the same
            const paymentsAfter = await prisma.payment.count({
                where: { orderId },
            });

            expect(paymentsAfter).toBe(paymentsBefore);
        });

        it('should reject webhook with invalid signature', async () => {
            const webhookPayload = createMockPaymobWebhook(orderId, true);
            const invalidSignature = 'invalid-signature-123';

            const response = await request(app.getHttpServer())
                .post('/api/payment/webhook')
                .set('x-paymob-signature', invalidSignature)
                .send(webhookPayload);

            expect(response.status).toBe(500);
            expect(response.body).toHaveProperty('success', false);
            expect(response.body.error).toBeDefined();
        });

        it('should handle wallet payment webhook', async () => {
            // Reset inventory
            await resetInventory();

            // Create order for wallet payment
            await prisma.cartItem.deleteMany({
                where: { cart: { customerId } },
            });
            await prisma.cart.deleteMany({ where: { customerId } });

            const cart = await prisma.cart.create({
                data: { customerId },
            });

            const variant = await prisma.productVariant.findFirst();
            await prisma.cartItem.create({
                data: {
                    cartId: cart.id,
                    variantId: variant!.id,
                    qty: 1,
                },
            });

            const billingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
            });
            const shippingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
                skip: 1,
            });

            const orderResponse = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddress!.id,
                    shippingAddressId: shippingAddress!.id,
                    currency: 'EGP',
                    paymentMethod: PAYMENTMETHOD.WALLET,
                });

            const walletOrder = expectSuccessResponse<any>(orderResponse, 201);

            const webhookPayload = {
                ...createMockPaymobWebhook(walletOrder.id, true),
                obj: {
                    ...createMockPaymobWebhook(walletOrder.id, true).obj,
                    source_data: {
                        type: 'wallet',
                        sub_type: 'vodafone_cash',
                    },
                },
            };

            const signature = generateWebhookSignature(
                webhookPayload,
                process.env.PAYMOB_API_KEY || 'test-key',
            );

            const response = await request(app.getHttpServer())
                .post('/api/payment/webhook')
                .set('x-paymob-signature', signature)
                .send(webhookPayload);

            expect(response.status).toBe(200);

            // Verify wallet payment was saved
            const payment = await prisma.payment.findFirst({
                where: { orderId: walletOrder.id },
            });

            expect(payment).toBeDefined();
            expect(payment?.method).toBe(PAYMENTMETHOD.WALLET);
            expect(payment?.status).toBe(PAYMENTSTATUS.PAID);
        });
    });

    describe('POST /payment/cash/:orderId (Record Cash Payment)', () => {
        let cashOrderId: string;

        beforeAll(async () => {
            // Reset inventory
            await resetInventory();

            // Create cash on delivery order
            await prisma.cartItem.deleteMany({
                where: { cart: { customerId } },
            });
            await prisma.cart.deleteMany({ where: { customerId } });

            const cart = await prisma.cart.create({
                data: { customerId },
            });

            const variant = await prisma.productVariant.findFirst();
            await prisma.cartItem.create({
                data: {
                    cartId: cart.id,
                    variantId: variant!.id,
                    qty: 1,
                },
            });

            const billingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
            });
            const shippingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
                skip: 1,
            });

            const orderResponse = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddress!.id,
                    shippingAddressId: shippingAddress!.id,
                    currency: 'EGP',
                    paymentMethod: PAYMENTMETHOD.CASH_ON_DELIVERY,
                });

            const cashOrder = expectSuccessResponse<any>(orderResponse, 201);
            cashOrderId = cashOrder.id;
        });

        it('should record cash payment by admin', async () => {
            const response = await request(app.getHttpServer())
                .post(`/api/payment/cash/${cashOrderId}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    amount: 100,
                    currency: 'EGP',
                });

            expect(response.status).toBe(200);
            expect(response.body).toHaveProperty('success', true);
            expect(response.body).toHaveProperty(
                'message',
                'Cash payment recorded successfully',
            );

            // Verify cash payment was recorded
            const payment = await prisma.payment.findFirst({
                where: {
                    orderId: cashOrderId,
                    method: PAYMENTMETHOD.CASH_ON_DELIVERY,
                },
            });

            expect(payment).toBeDefined();
            expect(payment?.status).toBe(PAYMENTSTATUS.PAID);
            expect(Number(payment?.amount)).toBe(100);

            // Verify order payment status was updated
            await dispatchOutboxEvents();
            const order = await prisma.order.findUnique({
                where: { id: cashOrderId },
            });

            expect(order?.paymentStatus).toBe(PAYMENTSTATUS.PAID);
        });

        it('should return 401 if not authenticated', async () => {
            const response = await request(app.getHttpServer())
                .post(`/api/payment/cash/${cashOrderId}`)
                .send({
                    amount: 100,
                    currency: 'EGP',
                });

            expectErrorResponse(response, 401);
        });

        it('should return 400 for invalid amount', async () => {
            const response = await request(app.getHttpServer())
                .post(`/api/payment/cash/${cashOrderId}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    amount: -100, // Negative amount
                    currency: 'EGP',
                });

            expectErrorResponse(response, 400);
        });

        it('should return 400 for duplicate cash payment', async () => {
            const response = await request(app.getHttpServer())
                .post(`/api/payment/cash/${cashOrderId}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    amount: 100,
                    currency: 'EGP',
                });

            expectErrorResponse(response, 400);
        });

        it('should return 404 for non-existent order', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/payment/cash/00000000-0000-0000-0000-000000000000')
                .set('Authorization', `Bearer ${adminToken}`)
                .send({
                    amount: 100,
                    currency: 'EGP',
                });

            expectErrorResponse(response, 404);
        });
    });

    describe('Payment Integration with Orders', () => {
        it('should create order with card payment and return payment URL', async () => {
            // Reset inventory
            await resetInventory();

            // Clean cart
            await prisma.cartItem.deleteMany({
                where: { cart: { customerId } },
            });
            await prisma.cart.deleteMany({ where: { customerId } });

            const cart = await prisma.cart.create({
                data: { customerId },
            });

            const variant = await prisma.productVariant.findFirst();
            await prisma.cartItem.create({
                data: {
                    cartId: cart.id,
                    variantId: variant!.id,
                    qty: 2,
                },
            });

            const billingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
            });
            const shippingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
                skip: 1,
            });

            const response = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddress!.id,
                    shippingAddressId: shippingAddress!.id,
                    currency: 'EGP',
                    paymentMethod: PAYMENTMETHOD.CARD,
                });

            const order = expectSuccessResponse<any>(response, 201);

            // Should have payment URL for card payment
            expect(order).toHaveProperty('paymentUrl');
            expect(order.paymentUrl).toContain('paymob.com');
            expect(order.paymentUrl).toContain('payment_token');
        });

        it('should create order with wallet payment and return payment URL', async () => {
            // Reset inventory
            await resetInventory();

            // Clean cart
            await prisma.cartItem.deleteMany({
                where: { cart: { customerId } },
            });
            await prisma.cart.deleteMany({ where: { customerId } });

            const cart = await prisma.cart.create({
                data: { customerId },
            });

            const variant = await prisma.productVariant.findFirst();
            await prisma.cartItem.create({
                data: {
                    cartId: cart.id,
                    variantId: variant!.id,
                    qty: 1,
                },
            });

            const billingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
            });
            const shippingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
                skip: 1,
            });

            const response = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddress!.id,
                    shippingAddressId: shippingAddress!.id,
                    currency: 'EGP',
                    paymentMethod: PAYMENTMETHOD.WALLET,
                });

            const order = expectSuccessResponse<any>(response, 201);

            // Should have payment URL for wallet payment
            expect(order).toHaveProperty('paymentUrl');
            expect(typeof order.paymentUrl).toBe('string');
        });

        it('should create order with cash on delivery and return null payment URL', async () => {
            // Reset inventory
            await resetInventory();

            // Clean cart
            await prisma.cartItem.deleteMany({
                where: { cart: { customerId } },
            });
            await prisma.cart.deleteMany({ where: { customerId } });

            const cart = await prisma.cart.create({
                data: { customerId },
            });

            const variant = await prisma.productVariant.findFirst();
            await prisma.cartItem.create({
                data: {
                    cartId: cart.id,
                    variantId: variant!.id,
                    qty: 1,
                },
            });

            const billingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
            });
            const shippingAddress = await prisma.address.findFirst({
                where: { userId: customerId },
                skip: 1,
            });

            const response = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddress!.id,
                    shippingAddressId: shippingAddress!.id,
                    currency: 'EGP',
                    paymentMethod: PAYMENTMETHOD.CASH_ON_DELIVERY,
                });

            const order = expectSuccessResponse<any>(response, 201);

            // Should NOT have payment URL for cash on delivery
            expect(order.paymentUrl).toBeNull();
        });
    });
});
