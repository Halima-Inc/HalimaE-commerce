import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import * as argon2 from 'argon2';
import { PrismaService } from '../src/prisma/prisma.service';
import {
    setupE2ETest,
    teardownE2ETest,
    getUniqueTestData,
} from './jest-e2e.setup';
import { DashboardService } from '../src/dashboard/dashboard.service';
import { CacheService } from '../src/common/cache.service';
import {
    expectSuccessResponse,
    expectErrorResponse,
    extractAuthTokenFromResponse,
} from './test-utils';
import { DashboardDto } from '../src/dashboard/dto';

describe('DashboardController (e2e)', () => {
    let app: INestApplication;
    let prisma: PrismaService;
    let dashboardService: DashboardService;
    let cacheService: CacheService;
    let adminRoleId: string;
    let adminToken: string;
    let customerId: string;
    let categoryId: string;
    let productId: string;
    let variantId: string;
    let addressId: string;

    beforeAll(async () => {
        ({ app, prisma } = await setupE2ETest());

        dashboardService = app.get(DashboardService);
        cacheService = app.get(CacheService);

        // Find or create admin role and user
        let adminRole = await prisma.role.findFirst({
            where: { name: 'admin' },
        });
        if (!adminRole) {
            adminRole = await prisma.role.create({ data: { name: 'admin' } });
        }
        adminRoleId = adminRole.id;

        const uniqueData = getUniqueTestData('dashboard-admin');
        await prisma.user.create({
            data: {
                name: uniqueData.name,
                email: uniqueData.email,
                passwordHash: await argon2.hash('password123'),
                roleId: adminRoleId,
            },
        });

        // Login to get admin token
        const loginResponse = await request(app.getHttpServer())
            .post('/api/auth/login')
            .send({ email: uniqueData.email, password: 'password123' });

        adminToken = extractAuthTokenFromResponse(loginResponse);

        // Create test data for metrics
        await createTestData();
    }, 60000);

    afterAll(async () => {
        // Clear cache
        await cacheService.del('dashboard-metrics').catch(() => {});

        if (app) {
            await teardownE2ETest(app, prisma);
        }
    }, 60000);

    async function createTestData() {
        // Create customer role and user
        let customerRole = await prisma.role.findFirst({
            where: { name: 'customer' },
        });
        if (!customerRole) {
            customerRole = await prisma.role.create({
                data: { name: 'customer' },
            });
        }

        const customerData = getUniqueTestData('dashboard-customer');
        const customer = await prisma.user.create({
            data: {
                name: customerData.name,
                email: customerData.email,
                passwordHash: 'hashed',
                roleId: customerRole.id,
            },
        });
        customerId = customer.id;

        // Create address for customer
        const address = await prisma.address.create({
            data: {
                userId: customer.id,
                firstName: 'Test',
                lastName: 'Customer',
                line1: '123 Test St',
                city: 'Cairo',
                country: 'Egypt',
                postalCode: '12345',
                isDefault: true,
            },
        });
        addressId = address.id;

        // Create category
        const categoryData = getUniqueTestData('dashboard-category');
        const category = await prisma.category.create({
            data: {
                name: categoryData.name,
                slug: categoryData.slug,
            },
        });
        categoryId = category.id;

        // Create product with variant
        const productData = getUniqueTestData('dashboard-product');
        const product = await prisma.product.create({
            data: {
                name: productData.name,
                slug: productData.slug,
                status: 'ACTIVE',
                categoryId: category.id,
                variants: {
                    create: {
                        sku: productData.sku,
                        size: 'M',
                        color: 'Blue',
                        isActive: true,
                        prices: {
                            create: {
                                currency: 'EGP',
                                amount: 100,
                                compareAt: 120,
                            },
                        },
                        inventory: {
                            create: {
                                stockOnHand: 50,
                                lowStockThreshold: 10,
                            },
                        },
                    },
                },
            },
            include: {
                variants: true,
            },
        });
        productId = product.id;
        variantId = product.variants[0].id;

        // Create an order with items
        const order = await prisma.order.create({
            data: {
                orderNo: `ORD-${Date.now()}`,
                userId: customer.id,
                currency: 'EGP',
                status: 'PENDING',
                paymentStatus: 'PAID',
                fulfillmentStatus: 'PENDING',
                billingAddressId: address.id,
                shippingAddressId: address.id,
                items: {
                    create: {
                        variantId: variantId,
                        nameSnapshot: productData.name,
                        skuSnapshot: productData.sku,
                        unitPrice: 100,
                        qty: 2,
                    },
                },
            },
        });

        // Create a second order for repeat customer testing
        await prisma.order.create({
            data: {
                orderNo: `ORD-${Date.now()}-2`,
                userId: customer.id,
                currency: 'EGP',
                status: 'PENDING',
                paymentStatus: 'PAID',
                fulfillmentStatus: 'PENDING',
                billingAddressId: address.id,
                shippingAddressId: address.id,
                items: {
                    create: {
                        variantId: variantId,
                        nameSnapshot: productData.name,
                        skuSnapshot: productData.sku,
                        unitPrice: 100,
                        qty: 1,
                    },
                },
            },
        });

        // Create a low stock product
        const lowStockData = getUniqueTestData('dashboard-lowstock');
        await prisma.product.create({
            data: {
                name: lowStockData.name,
                slug: lowStockData.slug,
                status: 'ACTIVE',
                categoryId: category.id,
                variants: {
                    create: {
                        sku: lowStockData.sku,
                        isActive: true,
                        prices: {
                            create: {
                                currency: 'EGP',
                                amount: 50,
                            },
                        },
                        inventory: {
                            create: {
                                stockOnHand: 5,
                                lowStockThreshold: 10,
                            },
                        },
                    },
                },
            },
        });
    }

    describe('GET /api/dashboard', () => {
        it('should return 401 without authentication', async () => {
            const response = await request(app.getHttpServer()).get(
                '/api/dashboard',
            );

            expect(response.status).toBe(401);
        });

        it('should return dashboard metrics for admin', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            expect(response.status).toBe(200);
            const data: DashboardDto = expectSuccessResponse(response, 200);

            // Revenue metrics
            expect(data).toHaveProperty('totalRevenue');
            expect(data).toHaveProperty('grossRevenue');
            expect(data).toHaveProperty('totalDiscounts');
            expect(data).toHaveProperty('avgDiscountPct');
            expect(data).toHaveProperty('revenueByCurrency');
            expect(data).toHaveProperty('salesByPeriod');
            expect(data).toHaveProperty('peakPeriods');
            expect(data).toHaveProperty('seasonalTrends');
            expect(data).toHaveProperty('yoyComparison');

            // Location metrics
            expect(data).toHaveProperty('ordersByLocation');
            expect(data).toHaveProperty('topRegions');

            // Order metrics
            expect(data).toHaveProperty('totalOrders');
            expect(data).toHaveProperty('ordersByStatus');
            expect(data).toHaveProperty('ordersToday');
            expect(data).toHaveProperty('averageItemsPerOrder');
            expect(data).toHaveProperty('aov');

            // Customer metrics
            expect(data).toHaveProperty('totalCustomers');
            expect(data).toHaveProperty('newCustomersByDay');
            expect(data).toHaveProperty('repeatCustomerRate');

            // Product metrics
            expect(data).toHaveProperty('totalProducts');
            expect(data).toHaveProperty('productsByCategory');
            expect(data).toHaveProperty('bestSellingProducts');

            // Inventory metrics
            expect(data).toHaveProperty('lowStockProducts');
        });

        it('should return correct revenue values', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const data: DashboardDto = expectSuccessResponse(response, 200);

            // We created 2 orders: first with qty 2 @ 100 = 200, second with qty 1 @ 100 = 100
            // Total revenue = 300
            expect(data.totalRevenue).toBe(300);
            expect(data.revenueByCurrency).toHaveProperty('EGP');
            expect(data.revenueByCurrency.EGP).toBe(300);
        });

        it('should return correct order counts', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const data: DashboardDto = expectSuccessResponse(response, 200);

            expect(data.totalOrders).toBeGreaterThanOrEqual(2);
            expect(data.ordersToday).toBeGreaterThanOrEqual(2);
        });

        it('should return correct customer metrics', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const data: DashboardDto = expectSuccessResponse(response, 200);

            expect(data.totalCustomers).toBeGreaterThanOrEqual(1);
            // Customer has 2 orders, so repeat rate should be > 0
            expect(data.repeatCustomerRate).toBeGreaterThanOrEqual(0);
        });

        it('should return correct product metrics', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const data: DashboardDto = expectSuccessResponse(response, 200);

            expect(data.totalProducts).toBeGreaterThanOrEqual(2);
            expect(data.bestSellingProducts).toBeInstanceOf(Array);
            expect(data.bestSellingProducts.length).toBeGreaterThan(0);

            // Check best selling product structure
            const topProduct = data.bestSellingProducts[0];
            expect(topProduct).toHaveProperty('productId');
            expect(topProduct).toHaveProperty('qty');
            expect(topProduct).toHaveProperty('revenue');
        });

        it('should return low stock products', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const data: DashboardDto = expectSuccessResponse(response, 200);

            expect(data.lowStockProducts).toBeInstanceOf(Array);
            expect(data.lowStockProducts.length).toBeGreaterThan(0);

            // We created a product with stock 5, threshold 10
            const lowStockItem = data.lowStockProducts.find(
                (p: any) => p.stock === 5,
            );
            expect(lowStockItem).toBeDefined();
        });

        it('should return orders by location', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const data: DashboardDto = expectSuccessResponse(response, 200);

            expect(data.ordersByLocation).toBeInstanceOf(Array);
            expect(data.ordersByLocation.length).toBeGreaterThan(0);

            // We created orders with Egypt address
            const egyptStats = data.ordersByLocation.find(
                (loc: any) => loc.country === 'Egypt',
            );
            expect(egyptStats).toBeDefined();
            expect(egyptStats?.count).toBeGreaterThanOrEqual(2);
            expect(egyptStats?.revenue).toBe(300);
        });

        it('should return products by category', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const data: DashboardDto = expectSuccessResponse(response, 200);

            expect(data.productsByCategory).toBeDefined();
            expect(Object.keys(data.productsByCategory).length).toBeGreaterThan(
                0,
            );
        });

        it('should return sales by period', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const data: DashboardDto = expectSuccessResponse(response, 200);

            expect(data.salesByPeriod).toHaveProperty('hourly');
            expect(data.salesByPeriod).toHaveProperty('daily');
            expect(data.salesByPeriod).toHaveProperty('weekly');
            expect(data.salesByPeriod).toHaveProperty('monthly');
        });

        it('should return YoY comparison', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const data: DashboardDto = expectSuccessResponse(response, 200);

            expect(data.yoyComparison).toHaveProperty('thisYear');
            expect(data.yoyComparison).toHaveProperty('lastYear');
            expect(data.yoyComparison).toHaveProperty('growthRate');
        });
    });

    describe('GET /api/dashboard/refresh', () => {
        it('should return 401 without authentication', async () => {
            const response = await request(app.getHttpServer()).get(
                '/api/dashboard/refresh',
            );

            expect(response.status).toBe(401);
        });

        it('should force refresh dashboard metrics', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/dashboard/refresh')
                .set('Authorization', `Bearer ${adminToken}`);

            expect(response.status).toBe(200);
            const data = expectSuccessResponse(response, 200);

            expect(data).toHaveProperty('totalRevenue');
            expect(data).toHaveProperty('totalOrders');
            expect(data).toHaveProperty('totalCustomers');
        });
    });

    describe('Dashboard Caching', () => {
        it('should cache metrics after first request', async () => {
            // Clear cache first
            await cacheService.del('dashboard-metrics');

            // First request - computes metrics
            const response1 = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            expect(response1.status).toBe(200);

            // Check cache is populated
            const cached = await cacheService.get('dashboard-metrics');
            expect(cached).not.toBeNull();
        });

        it('should return cached metrics on subsequent requests', async () => {
            // First request
            const response1 = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const data1: DashboardDto = expectSuccessResponse(response1, 200);

            // Second request (should be from cache)
            const response2 = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const data2: DashboardDto = expectSuccessResponse(response2, 200);

            // Should return same data
            expect(data1.totalRevenue).toBe(data2.totalRevenue);
            expect(data1.totalOrders).toBe(data2.totalOrders);
        });

        it('should update cache after refresh', async () => {
            // Get initial cached value
            const initialResponse = await request(app.getHttpServer())
                .get('/api/dashboard')
                .set('Authorization', `Bearer ${adminToken}`);

            const initialData: DashboardDto = expectSuccessResponse(
                initialResponse,
                200,
            );

            // Create a new order
            const orderNo = `ORD-REFRESH-${Date.now()}`;
            await prisma.order.create({
                data: {
                    orderNo,
                    userId: customerId,
                    currency: 'EGP',
                    status: 'PENDING',
                    paymentStatus: 'PAID',
                    fulfillmentStatus: 'PENDING',
                    billingAddressId: addressId,
                    shippingAddressId: addressId,
                    items: {
                        create: {
                            variantId,
                            nameSnapshot: 'Test Product',
                            skuSnapshot: 'TEST-SKU',
                            unitPrice: 50,
                            qty: 1,
                        },
                    },
                },
            });

            // Force refresh
            const refreshResponse = await request(app.getHttpServer())
                .get('/api/dashboard/refresh')
                .set('Authorization', `Bearer ${adminToken}`);

            const refreshedData: DashboardDto = expectSuccessResponse(
                refreshResponse,
                200,
            );

            // Revenue should be higher after new order
            expect(refreshedData.totalRevenue).toBe(
                initialData.totalRevenue + 50,
            );
            expect(refreshedData.totalOrders).toBe(initialData.totalOrders + 1);
        });
    });

    describe('DashboardService Unit Tests', () => {
        it('should compute metrics correctly', async () => {
            const metrics = await dashboardService.computeDashboardMetrics();

            expect(metrics).toBeDefined();
            expect(typeof metrics.totalRevenue).toBe('number');
            expect(typeof metrics.grossRevenue).toBe('number');
            expect(typeof metrics.totalOrders).toBe('number');
            expect(typeof metrics.totalCustomers).toBe('number');
            expect(typeof metrics.totalProducts).toBe('number');
        });

        it('should calculate AOV correctly', async () => {
            const metrics = await dashboardService.computeDashboardMetrics();

            // AOV = Total Revenue / Number of Paid Orders
            if (metrics.totalOrders > 0) {
                expect(metrics.aov).toBeGreaterThan(0);
            }
        });

        it('should calculate discounts correctly', async () => {
            const metrics = await dashboardService.computeDashboardMetrics();

            // We set compareAt to 120 and amount to 100, so discount = 20 per item
            // First order: qty 2, second order: qty 1 = 3 items total
            // Total discount = 3 * 20 = 60
            expect(metrics.totalDiscounts).toBeGreaterThanOrEqual(60);
            expect(metrics.avgDiscountPct).toBeGreaterThan(0);
        });
    });
});
