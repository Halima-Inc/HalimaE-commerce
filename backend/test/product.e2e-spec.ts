import { INestApplication, LoggerService, Logger } from '@nestjs/common';
import request from 'supertest';
import { PrismaService } from '../src/prisma/prisma.service';
import {
    CreateProductDto,
    ProductVariantDto,
} from '../src/product/presentation/dto';
import { Status, Prisma } from '@prisma/client';
import * as path from 'path';
import * as fs from 'fs';
import * as argon2 from 'argon2';
import { setupE2ETest, teardownE2ETest } from './jest-e2e.setup';
import { LogService } from '../src/common/log.service';
import { NestExpressApplication } from '@nestjs/platform-express';
import {
    expectSuccessResponse,
    expectErrorResponse,
    expectSuccessArrayResponse,
    expectSuccessPaginatedResponse,
    extractAuthTokenFromResponse,
    expectHttpStatus,
    expectSuccessMessage,
} from './test-utils';

describe('ProductController (e2e)', () => {
    let app: NestExpressApplication;
    let logger: LoggerService;
    let prisma: PrismaService;
    let authToken: string;
    let categoryId: string;
    let productId: string;
    let variantId: string;
    let imageId: string;

    const testImagePath = path.join(__dirname, 'test-image.png');

    beforeAll(async () => {
        // Create a valid 1x1 transparent PNG for testing uploads
        // The previous 'test' string was not a valid image format.
        const base64Image =
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';
        fs.writeFileSync(testImagePath, Buffer.from(base64Image, 'base64'));

        ({ app, prisma } = await setupE2ETest());
        logger = app.get<LoggerService>(LogService);

        // 2. Create a test user and get auth token
        let role = await prisma.role.findFirst({
            where: { name: 'admin' },
            select: { id: true },
        });
        if (!role) {
            role = await prisma.role.create({
                data: { name: 'admin' },
                select: { id: true },
            });
        }

        const passwordHash = await argon2.hash('password');

        const user = await prisma.user.upsert({
            where: { email: 'product-test@example.com' },
            update: {},
            create: {
                name: 'product admin',
                email: 'product-test@example.com',
                passwordHash: passwordHash,
                roleId: role.id,
            },
        });

        logger.debug?.(`User created: ${JSON.stringify(user)}`, 'E2E-Product');

        const loginResponse = await request(app.getHttpServer())
            .post('/api/auth/login')
            .send({ email: user.email, password: 'password' });

        authToken = extractAuthTokenFromResponse(loginResponse);

        // 3. Create a test category
        const category = await prisma.category.upsert({
            where: { slug: 'e2e-test-category' },
            update: {},
            create: { name: 'E2E Test Category', slug: 'e2e-test-category' },
        });
        categoryId = category.id;
        logger.log(
            `Category created: ${JSON.stringify(category)}`,
            'E2E-Product',
        );
    }, 30000);

    afterAll(async () => {
        // Clean up the dummy image file
        if (fs.existsSync(testImagePath)) {
            fs.unlinkSync(testImagePath);
        }
        await teardownE2ETest(app, prisma);
    });

    describe('POST /products', () => {
        it('should fail with 401 if not authenticated', () => {
            return request(app.getHttpServer())
                .post('/api/products')
                .expect(401)
                .expect((res) => {
                    expectErrorResponse(res, 401);
                });
        });

        it('should create a new product, then add images to it', async () => {
            // Step 1: Create the product with variants (no images)
            const variantDto: ProductVariantDto = {
                sku: 'E2E-TSHIRT-RED-L',
                size: 'L',
                color: 'Red',
                prices: [
                    { currency: 'EGP', amount: new Prisma.Decimal('25.99') },
                ],
                inventory: { stockOnHand: 100 },
                isActive: true,
                material: 'Cotton',
            };

            const createDto: CreateProductDto = {
                name: 'E2E Test T-Shirt',
                slug: 'e2e-test-t-shirt',
                description: 'A t-shirt for e2e testing.',
                status: Status.ACTIVE,
                categoryId: categoryId,
                variants: [variantDto],
            };
            logger.log(
                `Creating product with DTO: ${JSON.stringify(createDto)}`,
                'E2E-Product',
            );

            const createResponse = await request(app.getHttpServer())
                .post('/api/products')
                .set('Authorization', `Bearer ${authToken}`)
                .send(createDto);

            logger.log(
                `Create Response status: ${createResponse.status}`,
                'E2E-Product',
            );
            logger.log(
                `Create Response: ${JSON.stringify(createResponse.body)}`,
                'E2E-Product',
            );

            expect(createResponse.status).toBe(201);
            const productData = expectSuccessResponse<any>(createResponse, 201);
            expect(productData).toHaveProperty('id');
            expect(productData.name).toBe(createDto.name);
            expect(productData.variants).toHaveLength(1);
            expect(productData.images).toHaveLength(0); // No images yet

            // Save IDs for subsequent tests
            productId = productData.id;
            variantId = productData.variants[0].id;

            // Step 2a: Request upload URL
            const uploadUrlResponse = await request(app.getHttpServer())
                .post(`/api/products/${productId}/images/upload-url`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({ contentType: 'image/png' })
                .expect(201);

            const uploadUrlData = expectSuccessResponse<any>(
                uploadUrlResponse,
                201,
            );
            expect(uploadUrlData.uploadUrl).toBeDefined();
            expect(uploadUrlData.key).toBeDefined();

            // Step 2b: Finalize the upload
            const addImageResponse = await request(app.getHttpServer())
                .post(`/api/products/${productId}/images`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                    key: uploadUrlData.key,
                    alt: 'A test t-shirt',
                    sort: 1,
                })
                .expect(201);

            expect(addImageResponse.status).toBe(201);
            const imageData = expectSuccessResponse<any>(addImageResponse, 201);
            expect(imageData).toHaveProperty('id');
            expect(imageData.alt).toBe('A test t-shirt');

            imageId = imageData.id;

            // Step 3: Verify the image can be served via its URL
            const imageUrl = imageData.url;
            const serveImageResponse = await request(app.getHttpServer())
                .get(imageUrl) // The URL is relative, e.g., /images/products/....
                .expect(200);

            // Check if the content type is correct for the uploaded PNG
            expect(serveImageResponse.headers['content-type']).toBe(
                'image/png',
            );
        });

        it('should fail to create a product with a duplicate slug', async () => {
            const variantDto: ProductVariantDto = {
                sku: 'E2E-TSHIRT-RED-L-DUP',
                size: 'L',
                color: 'Red',
                prices: [
                    { currency: 'EGP', amount: new Prisma.Decimal('25.99') },
                ],
                inventory: { stockOnHand: 100 },
                isActive: true,
                material: 'Cotton',
            };

            const createDto: CreateProductDto = {
                name: 'E2E Test T-Shirt Duplicate',
                slug: 'e2e-test-t-shirt', // duplicate slug
                description: 'A duplicate t-shirt for e2e testing.',
                status: Status.ACTIVE,
                categoryId: categoryId,
                variants: [variantDto],
            };

            const response = await request(app.getHttpServer())
                .post('/api/products')
                .set('Authorization', `Bearer ${authToken}`)
                .send(createDto)
                .expect(409); // Conflict for duplicate entries

            expectErrorResponse(response, 409);
        });
    });

    describe('GET /products', () => {
        it('should get a list of products', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/products')
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.products).toBeInstanceOf(Array);
            expect(data.products.length).toBeGreaterThan(0);
            expect(data.meta).toBeDefined();
            // Verify variants contain all necessary fields
            const product = data.products[0];
            expect(product.variants).toBeInstanceOf(Array);
            if (product.variants.length > 0) {
                const variant = product.variants[0];
                expect(variant).toHaveProperty('sku');
                expect(variant).toHaveProperty('size');
                expect(variant).toHaveProperty('color');
                expect(variant).toHaveProperty('material');
            }
        });

        it('should filter products by categoryId', async () => {
            const response = await request(app.getHttpServer())
                .get(`/api/products?categoryId=${categoryId}`)
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.products).toHaveLength(1);
            expect(data.products[0].name).toBe('E2E Test T-Shirt');
        });

        it('should filter products by status', async () => {
            const response = await request(app.getHttpServer())
                .get(`/api/products?status=${Status.ACTIVE}`)
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.products.length).toBeGreaterThan(0);
            expect(data.products[0].status).toBe(Status.ACTIVE);
        });

        it('should filter products by price range', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/products?priceMin=20&priceMax=30')
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.products[0].name).toBe('E2E Test T-Shirt');
        });

        it('should filter products by name', async () => {
            const response = await request(app.getHttpServer())
                .get('/api/products?name=E2E Test T-Shirt')
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            expect(data.products[0].name).toBe('E2E Test T-Shirt');
        });
    });

    describe('GET /products/:id', () => {
        it('should get a single product by its ID', () => {
            return request(app.getHttpServer())
                .get(`/api/products/${productId}`)
                .expect(200)
                .expect((res) => {
                    const data = expectSuccessResponse<any>(res, 200);
                    expect(data.id).toBe(productId);
                    expect(data.name).toBe('E2E Test T-Shirt');
                    expect(data.variants).toBeInstanceOf(Array);
                    expect(data.variants.length).toBeGreaterThan(0);
                    // Verify variant fields are present
                    const variant = data.variants[0];
                    expect(variant).toHaveProperty('id');
                    expect(variant).toHaveProperty('sku');
                    expect(variant).toHaveProperty('size');
                    expect(variant).toHaveProperty('color');
                    expect(variant).toHaveProperty('material');
                    expect(variant).toHaveProperty('prices');
                    expect(variant).toHaveProperty('inventory');
                });
        });

        it('should return 404 for a non-existent product ID', () => {
            return request(app.getHttpServer())
                .get('/api/products/00000000-0000-0000-0000-000000000000')
                .expect(404)
                .expect((res) => {
                    expectErrorResponse(res, 404);
                });
        });
    });

    describe('GET /products/:id/variants', () => {
        it('should get variants for a specific product', () => {
            return request(app.getHttpServer())
                .get(`/api/products/${productId}/variants`)
                .expect(200)
                .expect((res) => {
                    const data = expectSuccessArrayResponse<any>(res, 200);
                    const variant = data[0];
                    expect(variant.id).toBe(variantId);
                    expect(variant).toHaveProperty('sku');
                    expect(variant).toHaveProperty('size');
                    expect(variant).toHaveProperty('color');
                    expect(variant).toHaveProperty('material');
                    expect(variant).toHaveProperty('isActive');
                    expect(variant).toHaveProperty('prices');
                    expect(variant.prices).toBeInstanceOf(Array);
                    expect(variant).toHaveProperty('inventory');
                    expect(variant.inventory).toHaveProperty('stockOnHand');
                });
        });
    });

    describe('GET /products/:id/images', () => {
        it('should get images for a specific product', () => {
            return request(app.getHttpServer())
                .get(`/api/products/${productId}/images`)
                .expect(200)
                .expect((res) => {
                    const data = expectSuccessArrayResponse<any>(res, 200);
                    expect(data[0].id).toBe(imageId);
                });
        });
    });

    describe('PATCH /products/:id', () => {
        it("should update a product's details", () => {
            return request(app.getHttpServer())
                .patch(`/api/products/${productId}`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({ name: 'Updated E2E Test T-Shirt' })
                .expect(200)
                .expect((res) => {
                    const data = expectSuccessResponse<any>(res, 200);
                    expect(data.name).toBe('Updated E2E Test T-Shirt');
                });
        });
    });

    describe('POST /products/:id/variants', () => {
        it('should add a new variant to an existing product', async () => {
            const newVariant: ProductVariantDto = {
                sku: 'E2E-TSHIRT-BLUE-M',
                color: 'Blue',
                size: 'M',
                prices: [
                    { currency: 'EGP', amount: new Prisma.Decimal('24.99') },
                ],
                inventory: { stockOnHand: 50 },
            };

            const response = await request(app.getHttpServer())
                .post(`/api/products/${productId}/variants`)
                .set('Authorization', `Bearer ${authToken}`)
                .send(newVariant)
                .expect(201);

            const data = expectSuccessResponse<any>(response, 201);
            expect(data.sku).toBe(newVariant.sku);
            expect(data.size).toBe(newVariant.size);
            expect(data.color).toBe(newVariant.color);
            expect(data).toHaveProperty('material');
            expect(data.inventory).toBeDefined();
            expect(data.inventory.stockOnHand).toBe(50);
        });

        it('should reject creating variant without inventory', async () => {
            const invalidVariant: any = {
                sku: 'E2E-TSHIRT-GREEN-S',
                color: 'Green',
                size: 'S',
                prices: [
                    { currency: 'EGP', amount: new Prisma.Decimal('22.99') },
                ],
                // Missing inventory - should fail
            };

            const response = await request(app.getHttpServer())
                .post(`/api/products/${productId}/variants`)
                .set('Authorization', `Bearer ${authToken}`)
                .send(invalidVariant)
                .expect(400);

            expectErrorResponse(response, 400);
            const errorMessage =
                response.body.message || response.body.error?.message || '';
            expect(errorMessage).toContain('inventory');
        });
    });

    describe('PATCH /products/:id/variants/:variantId', () => {
        it('should update a specific variant', () => {
            return request(app.getHttpServer())
                .patch(`/api/products/${productId}/variants/${variantId}`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({ sku: 'E2E-TSHIRT-RED-L-UPDATED' })
                .expect(200)
                .expect((res) => {
                    const data = expectSuccessResponse<any>(res, 200);
                    expect(data.sku).toBe('E2E-TSHIRT-RED-L-UPDATED');
                });
        });
    });

    describe('PATCH /products/:id/images/:imageId', () => {
        it('should replace an existing image', async () => {
            const originalImage = await prisma.productImage.findUnique({
                where: { id: imageId },
            });

            const response = await request(app.getHttpServer())
                .patch(`/api/products/${productId}/images/${imageId}`)
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                    key: `products/${productId}/replaced-image.png`,
                    alt: 'Replaced Alt Text',
                    sort: 2,
                })
                .expect(200);

            const data = expectSuccessResponse<any>(response, 200);
            // The URL should be different from the original one
            expect(data.url).not.toBe(originalImage?.url);
            expect(data.alt).toBe('Replaced Alt Text');
            expect(data.sort).toBe(2);
        });
    });

    describe('DELETE routes', () => {
        let newProductId: string;
        let newVariantId: string;
        let newImageId: string;

        beforeAll(async () => {
            // Create a dedicated product to test deletion of sub-resources
            const product = await prisma.product.create({
                data: {
                    name: 'To Be Deleted',
                    slug: 'to-be-deleted',
                    status: 'ACTIVE',
                    categoryId: categoryId,
                    description: 'This product will be deleted.',
                    variants: {
                        create: {
                            sku: 'DEL-VAR',
                            prices: { create: { currency: 'EGP', amount: 1 } },
                            inventory: { create: { stockOnHand: 10 } },
                        },
                    },
                    images: { create: { url: '/del-img.png', sort: 1 } },
                },
                include: { variants: true, images: true },
            });
            newProductId = product.id;
            newVariantId = product.variants[0].id;
            newImageId = product.images[0].id;
        });

        it('DELETE /products/:id/variants/:variantId -> should delete a variant', async () => {
            await request(app.getHttpServer())
                .delete(
                    `/api/products/${newProductId}/variants/${newVariantId}`,
                )
                .set('Authorization', `Bearer ${authToken}`)
                .expect(204);

            const variant = await prisma.productVariant.findUnique({
                where: { id: newVariantId },
            });
            expect(variant).toBeNull();
        });

        it('DELETE /products/:id/images/:imageId -> should delete an image', async () => {
            await request(app.getHttpServer())
                .delete(`/api/products/${newProductId}/images/${newImageId}`)
                .set('Authorization', `Bearer ${authToken}`)
                .expect(204);

            const image = await prisma.productImage.findUnique({
                where: { id: newImageId },
            });
            expect(image).toBeNull();
        });

        it('DELETE /products/:id -> should delete a product and all its assets', async () => {
            await request(app.getHttpServer())
                .delete(`/api/products/${productId}`)
                .set('Authorization', `Bearer ${authToken}`)
                .expect(204);

            const product = await prisma.product.findUnique({
                where: { id: productId },
            });
            expect(product).toBeNull();

            // Verify that associated variants are also gone (due to cascading delete)
            const variant = await prisma.productVariant.findUnique({
                where: { id: variantId },
            });
            expect(variant).toBeNull();
        });
    });
});
