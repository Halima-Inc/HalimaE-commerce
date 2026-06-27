import { INestApplication, LoggerService } from '@nestjs/common';
import request from 'supertest';
import {
    setupE2ETest,
    teardownE2ETest,
    getUniqueTestData,
} from './jest-e2e.setup';
import * as argon2 from 'argon2';
import { PrismaService } from '../src/prisma/prisma.service';
import { LogService } from '../src/common/log.service';
import {
    Status,
    ORDERSTATUS,
    PAYMENTSTATUS,
    FULFILLMENTSTATUS,
    PAYMENTMETHOD,
} from '@prisma/client';
import {
    expectSuccessResponse,
    expectErrorResponse,
    extractAuthTokenFromResponse,
} from './test-utils';

describe('OrderController (e2e)', () => {
    let app: INestApplication;
    let prisma: PrismaService;
    let customerToken: string;
    let customerId: string;
    let adminToken: string;
    let categoryId: string;
    let productId: string;
    let variantId: string;
    let billingAddressId: string;
    let shippingAddressId: string;
    let orderId: string;
    let orderNo: string;
    let logger: LoggerService;
    let testData: any;

    let customerRoleId: string;

    async function createCustomerUser(prefix: string) {
        const unique = getUniqueTestData(prefix);
        const customer = await prisma.user.create({
            data: {
                name: unique.name,
                email: unique.email,
                passwordHash: await argon2.hash('password123'),
                phone: '1234567890',
                status: Status.ACTIVE,
                roleId: customerRoleId,
            },
        });

        const loginResponse = await request(app.getHttpServer())
            .post('/api/auth/login')
            .send({ email: unique.email, password: 'password123' })
            .expect(200);

        const token = extractAuthTokenFromResponse(loginResponse);

        return {
            id: customer.id,
            token,
            email: unique.email,
            name: unique.name,
        };
    }

    beforeAll(async () => {
        ({ app, prisma } = await setupE2ETest());
        logger = app.get<LoggerService>(LogService);

        // Seed customer role
        let role = await prisma.role.findFirst({
            where: { name: 'customer' },
        });
        if (!role) {
            role = await prisma.role.create({
                data: { name: 'customer' },
            });
        }
        customerRoleId = role.id;

        testData = getUniqueTestData('order');

        // Create test customer
        const customer = await createCustomerUser('order');
        customerId = customer.id;
        customerToken = customer.token;

        // Create admin user
        const adminData = getUniqueTestData('admin');
        const adminRole = await prisma.role.create({
            data: {
                name: 'admin',
            },
        });

        const adminUser = await prisma.user.create({
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

        // Create addresses for customer
        const billingAddress = await prisma.address.create({
            data: {
                userId: customerId,
                firstName: 'John',
                lastName: 'Doe',
                phone: '1234567890',
                line1: '123 Billing St',
                city: 'Cairo',
                country: 'Egypt',
                postalCode: '12345',
            },
        });
        billingAddressId = billingAddress.id;

        const shippingAddress = await prisma.address.create({
            data: {
                userId: customerId,
                firstName: 'John',
                lastName: 'Doe',
                phone: '1234567890',
                line1: '456 Shipping Ave',
                city: 'Alexandria',
                country: 'Egypt',
                postalCode: '67890',
            },
        });
        shippingAddressId = shippingAddress.id;

        // Create test product
        const categoryData = getUniqueTestData('category');
        const category = await prisma.category.create({
            data: {
                name: categoryData.name,
                slug: categoryData.slug,
            },
        });
        categoryId = category.id;

        const productData = getUniqueTestData('product');
        const product = await prisma.product.create({
            data: {
                name: productData.name,
                slug: productData.slug,
                description: 'Test product for orders',
                status: Status.ACTIVE,
                categoryId: categoryId,
            },
        });
        productId = product.id;

        // Create variant with inventory
        const variantData = getUniqueTestData('variant');
        const variant = await prisma.productVariant.create({
            data: {
                productId: productId,
                sku: variantData.sku,
                size: 'M',
                color: 'Blue',
                material: 'Cotton',
                isActive: true,
            },
        });
        variantId = variant.id;

        // Create variant price
        await prisma.variantPrice.create({
            data: {
                variantId: variantId,
                currency: 'EGP',
                amount: 100.0,
                compareAt: 150.0,
            },
        });

        // Create variant inventory
        await prisma.variantInventory.create({
            data: {
                variantId: variantId,
                stockOnHand: 50,
            },
        });

        // Create cart with items
        const cart = await prisma.cart.create({
            data: {
                customerId: customerId,
            },
        });

        await prisma.cartItem.create({
            data: {
                cartId: cart.id,
                variantId: variantId,
                qty: 2,
            },
        });
    }, 30000);

    afterAll(async () => {
        await teardownE2ETest(app, prisma);
    });

    describe('POST /orders (Create Order)', () => {
        it('should create an order from customer cart with payment method', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddressId,
                    shippingAddressId: shippingAddressId,
                    currency: 'EGP',
                    paymentMethod: PAYMENTMETHOD.CASH_ON_DELIVERY, // Use cash for testing
                });

            expect(response.status).toBe(201);
            const data = expectSuccessResponse<any>(response, 201);

            expect(data).toHaveProperty('id');
            expect(data).toHaveProperty('orderNo');
            expect(data.customerId).toBe(customerId);
            expect(data.status).toBe(ORDERSTATUS.PENDING);
            expect(data.paymentStatus).toBe(PAYMENTSTATUS.PENDING);
            expect(data.fulfillmentStatus).toBe(FULFILLMENTSTATUS.PENDING);
            expect(data.currency).toBe('EGP');
            expect(data.items).toHaveLength(1);
            expect(data.items[0].qty).toBe(2);
            expect(Number(data.items[0].unitPrice)).toBe(100);
            expect(data.subtotal).toBe(200);
            expect(data.total).toBe(200);

            // For cash on delivery, paymentUrl should be null
            expect(data.paymentUrl).toBeNull();

            // Verify billing address snapshot
            expect(data.billingAddress).toHaveProperty('firstName', 'John');
            expect(data.billingAddress).toHaveProperty('lastName', 'Doe');
            expect(data.billingAddress).toHaveProperty(
                'line1',
                '123 Billing St',
            );

            // Verify shipping address snapshot
            expect(data.shippingAddress).toHaveProperty('firstName', 'John');
            expect(data.shippingAddress).toHaveProperty('lastName', 'Doe');
            expect(data.shippingAddress).toHaveProperty(
                'line1',
                '456 Shipping Ave',
            );

            orderId = data.id;
            orderNo = data.orderNo;
        });

        it('should decrement inventory after order creation', async () => {
            const inventory = await prisma.variantInventory.findUnique({
                where: { variantId: variantId },
            });

            // Initially 50, after order of 2: should be 48
            expect(inventory?.stockOnHand).toBe(48);
        });

        it('should clear cart after order creation', async () => {
            const cartResponse = await request(app.getHttpServer())
                .get('/api/cart')
                .set('Authorization', `Bearer ${customerToken}`);

            // Cart might be auto-created or return 404, both are acceptable
            // The important thing is that there are no items
            if (cartResponse.status === 200) {
                const cartData = expectSuccessResponse<any>(cartResponse, 200);
                expect(cartData.items).toHaveLength(0);
            } else {
                expectErrorResponse(cartResponse, 404);
            }
        });

        it('should return 400 if customer cart is empty', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddressId,
                    shippingAddressId: shippingAddressId,
                    paymentMethod: PAYMENTMETHOD.CASH_ON_DELIVERY,
                });

            expectErrorResponse(response, 400);
        });

        it('should return 400 if addresses do not belong to customer', async () => {
            // Create another customer with addresses
            const otherCustomer = await createCustomerUser('other-customer');

            const otherAddress = await prisma.address.create({
                data: {
                    userId: otherCustomer.id,
                    firstName: 'Jane',
                    lastName: 'Smith',
                    phone: '5555555555',
                    line1: '789 Other St',
                    city: 'Giza',
                    country: 'Egypt',
                    postalCode: '11111',
                },
            });

            // Clean up existing cart items and cart first
            await prisma.cartItem.deleteMany({
                where: { cart: { customerId: customerId } },
            });
            await prisma.cart.deleteMany({
                where: { customerId: customerId },
            });

            // Add items to current customer's cart
            const cart = await prisma.cart.create({
                data: { customerId: customerId },
            });

            await prisma.cartItem.create({
                data: {
                    cartId: cart.id,
                    variantId: variantId,
                    qty: 1,
                },
            });

            const response = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: otherAddress.id, // Wrong customer's address
                    shippingAddressId: shippingAddressId,
                    paymentMethod: PAYMENTMETHOD.CASH_ON_DELIVERY,
                });

            expectErrorResponse(response, 400);
        });

        it('should return 401 if not authenticated', async () => {
            const response = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .send({
                    billingAddressId: billingAddressId,
                    shippingAddressId: shippingAddressId,
                    paymentMethod: PAYMENTMETHOD.CASH_ON_DELIVERY,
                });

            expectErrorResponse(response, 401);
        });
    });

    describe('GET /orders/my-orders (Customer - Get All Orders)', () => {
        it('should get all orders for authenticated customer', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/orders/my-orders')
                .set('Authorization', `Bearer ${customerToken}`);

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data).toHaveProperty('orders');
            expect(data).toHaveProperty('meta');
            expect(Array.isArray(data.orders)).toBe(true);
            expect(data.orders.length).toBeGreaterThan(0);
            expect(data.orders[0]).toHaveProperty('id');
            expect(data.orders[0]).toHaveProperty('orderNo');
            expect(data.orders[0].customerId).toBe(customerId);
        });

        it('should return 401 if not authenticated', async () => {
            const response = await request(app.getHttpServer()).get(
                '/api/orders/my-orders',
            );

            expectErrorResponse(response, 401);
        });
    });

    describe('GET /orders/my-orders/:id (Customer - Get Order by ID)', () => {
        it('should get order by ID for authenticated customer', async () => {
            const response = await request(app.getHttpServer())
                .get(`/api/orders/my-orders/${orderId}`)
                .set('Authorization', `Bearer ${customerToken}`);

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data.id).toBe(orderId);
            expect(data.orderNo).toBe(orderNo);
            expect(data.customerId).toBe(customerId);
            expect(data.items).toBeDefined();
            expect(data.billingAddress).toBeDefined();
            expect(data.shippingAddress).toBeDefined();
        });

        it('should return 404 for non-existent order', async () => {
            const response = await request(app.getHttpServer())
                .get(
                    '/api/orders/my-orders/00000000-0000-0000-0000-000000000000',
                )
                .set('Authorization', `Bearer ${customerToken}`);

            expectErrorResponse(response, 404);
        });

        it("should return 404 if trying to access another customer's order", async () => {
            // Create another customer
            const otherCustomer = await createCustomerUser('other-customer-2');
            const otherToken = otherCustomer.token;

            const response = await request(app.getHttpServer())
                .get(`/api/orders/my-orders/${orderId}`)
                .set('Authorization', `Bearer ${otherToken}`);

            expectErrorResponse(response, 404);
        });
    });

    describe('GET /orders/my-orders/number/:orderNo (Customer - Get Order by Number)', () => {
        it('should get order by order number for authenticated customer', async () => {
            const response = await request(app.getHttpServer())
                .get(`/api/orders/my-orders/number/${orderNo}`)
                .set('Authorization', `Bearer ${customerToken}`);

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data.orderNo).toBe(orderNo);
            expect(data.customerId).toBe(customerId);
        });

        it('should return 404 for non-existent order number', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/orders/my-orders/number/INVALID-ORDER-NO')
                .set('Authorization', `Bearer ${customerToken}`);

            expectErrorResponse(response, 404);
        });
    });

    describe('PATCH /orders/my-orders/:id/cancel (Customer - Cancel Order)', () => {
        let cancelableOrderId: string;

        beforeAll(async () => {
            // Clean up existing cart items and cart first
            await prisma.cartItem.deleteMany({
                where: { cart: { customerId: customerId } },
            });
            await prisma.cart.deleteMany({
                where: { customerId: customerId },
            });

            // Create a new cart and order for cancellation test
            const cart = await prisma.cart.create({
                data: { customerId: customerId },
            });

            await prisma.cartItem.create({
                data: {
                    cartId: cart.id,
                    variantId: variantId,
                    qty: 3,
                },
            });

            const createResponse = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddressId,
                    shippingAddressId: shippingAddressId,
                    paymentMethod: PAYMENTMETHOD.CASH_ON_DELIVERY,
                });

            const data = expectSuccessResponse<any>(createResponse, 201);
            cancelableOrderId = data.id;
        });

        it('should cancel order in PENDING status', async () => {
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/my-orders/${cancelableOrderId}/cancel`)
                .set('Authorization', `Bearer ${customerToken}`);

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data.status).toBe(ORDERSTATUS.CANCELLED);
        });

        it('should restore inventory after order cancellation', async () => {
            const inventory = await prisma.variantInventory.findUnique({
                where: { variantId: variantId },
            });

            // After cancellation of 3 items, inventory should increase by 3
            // Was 48 after first order, then decreased by 3 (45), then restored by 3 (48)
            expect(inventory?.stockOnHand).toBe(48);
        });

        it('should return 400 if order is not in cancelable status', async () => {
            // Try to cancel already cancelled order
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/my-orders/${cancelableOrderId}/cancel`)
                .set('Authorization', `Bearer ${customerToken}`);

            expectErrorResponse(response, 400);
        });

        it('should return 404 for non-existent order', async () => {
            const response = await request(app.getHttpServer())
                .patch(
                    '/api/orders/my-orders/00000000-0000-0000-0000-000000000000/cancel',
                )
                .set('Authorization', `Bearer ${customerToken}`);

            expectErrorResponse(response, 404);
        });
    });

    describe('GET /orders/admin/all (Admin - Get All Orders)', () => {
        it('should get all orders for admin', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/orders/admin/all')
                .set('Authorization', `Bearer ${adminToken}`);

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data).toHaveProperty('orders');
            expect(data).toHaveProperty('meta');
            expect(Array.isArray(data.orders)).toBe(true);
            expect(data.orders.length).toBeGreaterThan(0);
            expect(data.orders[0]).toHaveProperty('id');
            expect(data.orders[0]).toHaveProperty('orderNo');
            expect(data.orders[0]).toHaveProperty('customerId');
        });

        it('should return 401 if not authenticated', async () => {
            const response = await request(app.getHttpServer()).get(
                '/api/orders/admin/all',
            );

            expectErrorResponse(response, 401);
        });

        it('should return 403 if customer tries to access', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/orders/admin/all')
                .set('Authorization', `Bearer ${customerToken}`);

            expectErrorResponse(response, 403);
        });
    });

    describe('GET /orders/admin/:id (Admin - Get Order by ID)', () => {
        it('should get any order by ID for admin', async () => {
            const response = await request(app.getHttpServer())
                .get(`/api/orders/admin/${orderId}`)
                .set('Authorization', `Bearer ${adminToken}`);

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            logger.debug?.(
                `Admin fetched order data: ${JSON.stringify(data)}`,
                'OrderService TEST',
            );
            expect(data.id).toBe(orderId);
            expect(data).toHaveProperty('customerId');
        });

        it('should return 404 for non-existent order', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/orders/admin/00000000-0000-0000-0000-000000000000')
                .set('Authorization', `Bearer ${adminToken}`);

            expectErrorResponse(response, 404);
        });
    });

    describe('GET /orders/admin/number/:orderNo (Admin - Get Order by Number)', () => {
        it('should get order by order number for admin', async () => {
            const response = await request(app.getHttpServer())
                .get(`/api/orders/admin/number/${orderNo}`)
                .set('Authorization', `Bearer ${adminToken}`);

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data.orderNo).toBe(orderNo);
        });

        it('should return 404 for non-existent order number', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/orders/admin/number/INVALID-ORDER-NO')
                .set('Authorization', `Bearer ${adminToken}`);

            expectErrorResponse(response, 404);
        });
    });

    describe('PATCH /orders/admin/:id/status (Admin - Update Order Status)', () => {
        it('should update order status to PROCESSING', async () => {
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${orderId}/status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ status: ORDERSTATUS.PROCESSING });

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data.status).toBe(ORDERSTATUS.PROCESSING);
        });

        it('should update order status to DELIVERED', async () => {
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${orderId}/status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ status: ORDERSTATUS.DELIVERED });

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data.status).toBe(ORDERSTATUS.DELIVERED);
        });

        it('should return 400 for invalid status', async () => {
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${orderId}/status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ status: 'INVALID_STATUS' });

            expectErrorResponse(response, 400);
        });

        it('should return 404 for non-existent order', async () => {
            const response = await request(app.getHttpServer())
                .patch(
                    '/api/orders/admin/00000000-0000-0000-0000-000000000000/status',
                )
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ status: ORDERSTATUS.PROCESSING });

            expectErrorResponse(response, 404);
        });

        it('should return 403 if customer tries to access', async () => {
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${orderId}/status`)
                .set('Authorization', `Bearer ${customerToken}`)
                .send({ status: ORDERSTATUS.PROCESSING });

            expectErrorResponse(response, 403);
        });
    });

    describe('PATCH /orders/admin/:id/payment-status (Admin - Update Payment Status)', () => {
        it('should update payment status to PAID', async () => {
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${orderId}/payment-status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ paymentStatus: PAYMENTSTATUS.PAID });

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data.paymentStatus).toBe(PAYMENTSTATUS.PAID);
        });

        it('should update payment status to REFUNDED', async () => {
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${orderId}/payment-status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ paymentStatus: PAYMENTSTATUS.REFUNDED });

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data.paymentStatus).toBe(PAYMENTSTATUS.REFUNDED);
        });

        it('should return 400 for invalid payment status', async () => {
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${orderId}/payment-status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ paymentStatus: 'INVALID_STATUS' });

            expectErrorResponse(response, 400);
        });

        it('should return 404 for non-existent order', async () => {
            const response = await request(app.getHttpServer())
                .patch(
                    '/api/orders/admin/00000000-0000-0000-0000-000000000000/payment-status',
                )
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ paymentStatus: PAYMENTSTATUS.PAID });

            expectErrorResponse(response, 404);
        });
    });

    describe('PATCH /orders/admin/:id/fulfillment-status (Admin - Update Fulfillment Status)', () => {
        it('should update fulfillment status to DELIVERED', async () => {
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${orderId}/fulfillment-status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ fulfillmentStatus: FULFILLMENTSTATUS.DELIVERED });

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data.fulfillmentStatus).toBe(FULFILLMENTSTATUS.DELIVERED);
        });

        it('should update fulfillment status to SHIPPED', async () => {
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${orderId}/fulfillment-status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ fulfillmentStatus: FULFILLMENTSTATUS.SHIPPED });

            expect(response.status).toBe(200);
            const data = expectSuccessResponse<any>(response, 200);

            expect(data.fulfillmentStatus).toBe(FULFILLMENTSTATUS.SHIPPED);
        });

        it('should return 400 for invalid fulfillment status', async () => {
            const response = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${orderId}/fulfillment-status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ fulfillmentStatus: 'INVALID_STATUS' });

            expectErrorResponse(response, 400);
        });

        it('should return 404 for non-existent order', async () => {
            const response = await request(app.getHttpServer())
                .patch(
                    '/api/orders/admin/00000000-0000-0000-0000-000000000000/fulfillment-status',
                )
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ fulfillmentStatus: FULFILLMENTSTATUS.DELIVERED });

            expectErrorResponse(response, 404);
        });
    });

    describe('Order Flow Integration', () => {
        it('should complete full order lifecycle', async () => {
            // Ensure we have enough inventory for this test
            await prisma.variantInventory.update({
                where: { variantId: variantId },
                data: { stockOnHand: 100 }, // Reset inventory
            });

            // Clean up existing cart items and cart first
            await prisma.cartItem.deleteMany({
                where: { cart: { customerId: customerId } },
            });
            await prisma.cart.deleteMany({
                where: { customerId: customerId },
            });

            // 1. Create cart and add items
            const cart = await prisma.cart.create({
                data: { customerId: customerId },
            });

            await prisma.cartItem.create({
                data: {
                    cartId: cart.id,
                    variantId: variantId,
                    qty: 5,
                },
            });

            // 2. Create order
            const createResponse = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddressId,
                    shippingAddressId: shippingAddressId,
                    currency: 'EGP',
                    paymentMethod: PAYMENTMETHOD.CASH_ON_DELIVERY,
                });

            if (createResponse.status !== 201) {
                console.error('Order creation failed in lifecycle test:', {
                    status: createResponse.status,
                    body: createResponse.body,
                    addresses: { billingAddressId, shippingAddressId },
                    customerId,
                });
            }

            const order = expectSuccessResponse<any>(createResponse, 201);
            expect(order.status).toBe(ORDERSTATUS.PENDING);
            expect(order.paymentStatus).toBe(PAYMENTSTATUS.PENDING);
            expect(order.fulfillmentStatus).toBe(FULFILLMENTSTATUS.PENDING);

            // 3. Admin updates order status to PROCESSING
            const processingResponse = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${order.id}/status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ status: ORDERSTATUS.PROCESSING });

            const processingOrder = expectSuccessResponse<any>(
                processingResponse,
                200,
            );
            expect(processingOrder.status).toBe(ORDERSTATUS.PROCESSING);

            // 4. Payment is marked as PAID
            const paidResponse = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${order.id}/payment-status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ paymentStatus: PAYMENTSTATUS.PAID });

            const paidOrder = expectSuccessResponse<any>(paidResponse, 200);
            expect(paidOrder.paymentStatus).toBe(PAYMENTSTATUS.PAID);

            // 5. Order is marked as SHIPPED
            const shippedResponse = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${order.id}/fulfillment-status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ fulfillmentStatus: FULFILLMENTSTATUS.SHIPPED });

            const shippedOrder = expectSuccessResponse<any>(
                shippedResponse,
                200,
            );
            expect(shippedOrder.fulfillmentStatus).toBe(
                FULFILLMENTSTATUS.SHIPPED,
            );

            // 6. Order is marked as DELIVERED (final fulfillment status)
            const deliveredResponse = await request(app.getHttpServer())
                .patch(`/api/orders/admin/${order.id}/fulfillment-status`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ fulfillmentStatus: FULFILLMENTSTATUS.DELIVERED });

            const deliveredOrder = expectSuccessResponse<any>(
                deliveredResponse,
                200,
            );
            expect(deliveredOrder.fulfillmentStatus).toBe(
                FULFILLMENTSTATUS.DELIVERED,
            );

            // 7. Verify order status was automatically updated to DELIVERED
            // (Order status is automatically updated when fulfillment status is set to DELIVERED)
            const verifyResponse = await request(app.getHttpServer())
                .get(`/api/orders/admin/${order.id}`)
                .set('Authorization', `Bearer ${adminToken}`);

            const verifiedOrder = expectSuccessResponse<any>(
                verifyResponse,
                200,
            );
            expect(verifiedOrder.status).toBe(ORDERSTATUS.DELIVERED);

            // 8. Customer retrieves delivered order
            const customerOrderResponse = await request(app.getHttpServer())
                .get(`/api/orders/my-orders/${order.id}`)
                .set('Authorization', `Bearer ${customerToken}`);

            const customerOrder = expectSuccessResponse<any>(
                customerOrderResponse,
                200,
            );
            expect(customerOrder.status).toBe(ORDERSTATUS.DELIVERED);
            expect(customerOrder.paymentStatus).toBe(PAYMENTSTATUS.PAID);
            expect(customerOrder.fulfillmentStatus).toBe(
                FULFILLMENTSTATUS.DELIVERED,
            );
        });

        it('should handle order cancellation and inventory restoration', async () => {
            // Ensure we have enough inventory for this test
            await prisma.variantInventory.update({
                where: { variantId: variantId },
                data: { stockOnHand: 100 }, // Reset inventory
            });

            // Get current inventory
            const inventoryBefore = await prisma.variantInventory.findUnique({
                where: { variantId: variantId },
            });

            // Clean up existing cart items and cart first
            await prisma.cartItem.deleteMany({
                where: { cart: { customerId: customerId } },
            });
            await prisma.cart.deleteMany({
                where: { customerId: customerId },
            });

            // Create order
            const cart = await prisma.cart.create({
                data: { customerId: customerId },
            });

            await prisma.cartItem.create({
                data: {
                    cartId: cart.id,
                    variantId: variantId,
                    qty: 10,
                },
            });

            const createResponse = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddressId,
                    shippingAddressId: shippingAddressId,
                    paymentMethod: PAYMENTMETHOD.CASH_ON_DELIVERY,
                });

            const order = expectSuccessResponse<any>(createResponse, 201);

            // Verify inventory decreased
            const inventoryAfterOrder =
                await prisma.variantInventory.findUnique({
                    where: { variantId: variantId },
                });
            expect(inventoryAfterOrder?.stockOnHand).toBe(
                inventoryBefore!.stockOnHand - 10,
            );

            // Cancel order
            const cancelResponse = await request(app.getHttpServer())
                .patch(`/api/orders/my-orders/${order.id}/cancel`)
                .set('Authorization', `Bearer ${customerToken}`);

            expectSuccessResponse<any>(cancelResponse, 200);

            // Verify inventory restored
            const inventoryAfterCancel =
                await prisma.variantInventory.findUnique({
                    where: { variantId: variantId },
                });
            expect(inventoryAfterCancel?.stockOnHand).toBe(
                inventoryBefore!.stockOnHand,
            );
        });

        it('should prevent order creation with insufficient inventory', async () => {
            // Set low inventory for this test
            await prisma.variantInventory.update({
                where: { variantId: variantId },
                data: { stockOnHand: 5 }, // Low inventory
            });

            // Get current inventory
            const inventory = await prisma.variantInventory.findUnique({
                where: { variantId: variantId },
            });

            // Clean up existing cart items and cart first
            await prisma.cartItem.deleteMany({
                where: { cart: { customerId: customerId } },
            });
            await prisma.cart.deleteMany({
                where: { customerId: customerId },
            });

            // Try to order more than available
            const cart = await prisma.cart.create({
                data: { customerId: customerId },
            });

            await prisma.cartItem.create({
                data: {
                    cartId: cart.id,
                    variantId: variantId,
                    qty: inventory!.stockOnHand + 100, // More than available
                },
            });

            const response = await request(app.getHttpServer())
                .post('/api/orders/checkout')
                .set('Authorization', `Bearer ${customerToken}`)
                .send({
                    billingAddressId: billingAddressId,
                    shippingAddressId: shippingAddressId,
                    paymentMethod: PAYMENTMETHOD.CASH_ON_DELIVERY,
                });

            expectErrorResponse(response, 400);
        });
    });

    describe('Order Security', () => {
        it('should not allow customer to access admin endpoints', async () => {
            const endpoints = [
                { method: 'get', url: '/api/orders/admin/all' },
                { method: 'get', url: `/api/orders/admin/${orderId}` },
                { method: 'get', url: `/api/orders/admin/number/${orderNo}` },
            ];

            for (const endpoint of endpoints) {
                const response = await (request(app.getHttpServer()) as any)
                    [endpoint.method](endpoint.url)
                    .set('Authorization', `Bearer ${customerToken}`)
                    .send({ status: ORDERSTATUS.PROCESSING });

                expectErrorResponse(response, 403);
            }
        });

        it('should allow admin to use customer endpoints (checking their own orders)', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/orders/my-orders')
                .set('Authorization', `Bearer ${adminToken}`);

            expect(response.status).toBe(200);
        });

        it('should not allow unauthenticated access to any order endpoint', async () => {
            const endpoints = [
                {
                    method: 'post',
                    url: '/api/orders/checkout',
                    expectedStatus: 401,
                },
                {
                    method: 'get',
                    url: '/api/orders/my-orders',
                    expectedStatus: 401,
                },
                {
                    method: 'get',
                    url: `/api/orders/my-orders/${orderId}`,
                    expectedStatus: 401,
                },
                {
                    method: 'get',
                    url: '/api/orders/admin/all',
                    expectedStatus: 401,
                },
            ];

            for (const endpoint of endpoints) {
                const response = await (request(app.getHttpServer()) as any)[
                    endpoint.method
                ](endpoint.url);

                expectErrorResponse(response, endpoint.expectedStatus);
            }
        });
    });
});
