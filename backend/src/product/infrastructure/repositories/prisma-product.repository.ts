import { Inject, Injectable } from '@nestjs/common';
import { Prisma, Status } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import {
    CreateProductAggregateInput,
    IProductRepository,
    ProductListFilters,
} from '../../domain/interfaces';
import { Product, type ProductRecord } from '../../domain/entities';
import { STORAGE_SERVICE } from '../../product.tokens';
import type { IStorageService } from '../../application/services';
import {
    ProductNotFoundException,
    ProductValidationException,
} from '../../domain/exceptions';

const productViewSelect = {
    id: true,
    name: true,
    slug: true,
    description: true,
    status: true,
    categoryId: true,
    createdAt: true,
    updatedAt: true,
    images: {
        select: {
            id: true,
            url: true,
            alt: true,
        },
    },
    variants: {
        select: {
            id: true,
            sku: true,
            size: true,
            color: true,
            material: true,
            isActive: true,
            prices: {
                select: {
                    id: true,
                    compareAt: true,
                    amount: true,
                    currency: true,
                },
            },
            inventory: {
                select: {
                    id: true,
                    stockOnHand: true,
                },
            },
        },
    },
} as const;

type ProductSelectRecord = Prisma.ProductGetPayload<{
    select: typeof productViewSelect;
}>;

function mapProductRecord(record: ProductSelectRecord): Product {
    const normalized: ProductRecord = {
        id: record.id,
        name: record.name,
        slug: record.slug,
        description: record.description,
        status: record.status,
        categoryId: record.categoryId,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
        images: record.images.map((image) => ({
            id: image.id,
            productId: record.id,
            url: image.url,
            alt: image.alt,
        })),
        variants: record.variants.map((variant) => ({
            id: variant.id,
            sku: variant.sku,
            size: variant.size,
            color: variant.color,
            material: variant.material,
            isActive: variant.isActive,
            prices: variant.prices.map((price) => ({
                id: price.id,
                compareAt: price.compareAt,
                amount: price.amount,
                currency: price.currency,
            })),
            inventory: variant.inventory
                ? {
                      id: variant.inventory.id,
                      stockOnHand: variant.inventory.stockOnHand,
                  }
                : null,
            productId: record.id,
        })),
    };

    return Product.create(normalized);
}

@Injectable()
export class PrismaProductRepository implements IProductRepository {
    constructor(
        private readonly prisma: PrismaService,
        @Inject(STORAGE_SERVICE)
        private readonly storageService: IStorageService,
    ) {}

    async findPaged(filters: ProductListFilters): Promise<{
        totalProducts: number;
        products: Product[];
    }> {
        const where = this.buildWhereClause(filters);
        const skip = (filters.page - 1) * filters.pageSize;

        const [totalProducts, products] = await this.prisma.$transaction([
            this.prisma.product.count({ where }),
            this.prisma.product.findMany({
                where,
                skip,
                take: filters.pageSize,
                select: productViewSelect,
                orderBy: { createdAt: 'desc' },
            }),
        ]);

        return {
            totalProducts,
            products: products.map((product) => mapProductRecord(product)),
        };
    }

    async findById(id: string): Promise<Product | null> {
        const product = await this.prisma.product.findUnique({
            where: { id },
            select: productViewSelect,
        });

        return product ? mapProductRecord(product) : null;
    }

    async updateById(
        id: string,
        data: {
            name?: string;
            slug?: string;
            description?: string | null;
            status?: Status;
            categoryId?: string;
        },
    ): Promise<Product> {
        const product = await this.prisma.product.update({
            where: { id },
            data,
            select: productViewSelect,
        });

        return mapProductRecord(product);
    }

    async createWithVariants(
        input: CreateProductAggregateInput,
    ): Promise<Product | null> {
        return this.prisma.$transaction(async (tx) => {
            const product = await tx.product.create({
                data: {
                    name: input.name,
                    slug: input.slug,
                    description: input.description,
                    status: input.status,
                    categoryId: input.categoryId,
                },
                select: {
                    id: true,
                },
            });

            for (const variant of input.variants) {
                if (
                    !Array.isArray(variant.prices) ||
                    variant.prices.length === 0
                ) {
                    throw new ProductValidationException(
                        'Variant must include at least one price',
                    );
                }

                if (
                    !variant.inventory ||
                    variant.inventory.stockOnHand === null ||
                    variant.inventory.stockOnHand === undefined
                ) {
                    throw new ProductValidationException(
                        'Variant must include inventory with stockOnHand',
                    );
                }

                await tx.productVariant.create({
                    data: {
                        sku: variant.sku,
                        size: variant.size,
                        color: variant.color,
                        material: variant.material,
                        isActive: variant.isActive ?? true,
                        product: {
                            connect: { id: product.id },
                        },
                        prices: {
                            create: variant.prices.map((price) => ({
                                currency: price.currency!,
                                amount: price.amount!,
                                compareAt: price.compareAt,
                            })),
                        },
                        inventory: {
                            create: {
                                stockOnHand: variant.inventory.stockOnHand,
                            },
                        },
                    },
                });
            }

            const created = await tx.product.findUnique({
                where: { id: product.id },
                select: productViewSelect,
            });

            return created ? mapProductRecord(created) : null;
        });
    }

    async deleteWithRelations(id: string): Promise<void> {
        await this.prisma.$transaction(async (tx) => {
            const snapshot = await tx.product.findUnique({
                where: { id },
                select: {
                    id: true,
                    images: {
                        select: {
                            url: true,
                        },
                    },
                    variants: {
                        select: {
                            id: true,
                        },
                    },
                },
            });

            if (!snapshot) {
                throw new ProductNotFoundException(
                    `Product with ID ${id} not found.`,
                );
            }

            const variantIds = snapshot.variants.map((variant) => variant.id);
            if (variantIds.length > 0) {
                await tx.variantPrice.deleteMany({
                    where: {
                        variantId: {
                            in: variantIds,
                        },
                    },
                });
                await tx.variantInventory.deleteMany({
                    where: {
                        variantId: {
                            in: variantIds,
                        },
                    },
                });
                await tx.productVariant.deleteMany({
                    where: {
                        id: {
                            in: variantIds,
                        },
                    },
                });
            }

            const imageKeys = snapshot.images
                .map((image) => this.extractKeyFromUrl(image.url))
                .filter((key): key is string => Boolean(key));

            await tx.productImage.deleteMany({
                where: { productId: id },
            });

            for (const key of imageKeys) {
                await this.storageService.deleteObject(key);
            }

            await tx.product.delete({
                where: { id },
            });
        });
    }

    async existsById(id: string): Promise<boolean> {
        const product = await this.prisma.product.findUnique({
            where: { id },
            select: { id: true },
        });

        return Boolean(product);
    }

    private buildWhereClause(
        filters: ProductListFilters,
    ): Prisma.ProductWhereInput {
        const where: Prisma.ProductWhereInput = {};

        if (filters.name) {
            where.name = {
                contains: filters.name,
                mode: 'insensitive',
            };
        }

        if (filters.categoryId) {
            where.categoryId = filters.categoryId;
        }

        if (filters.status) {
            where.status = filters.status;
        }

        const hasPriceMin = typeof filters.priceMin === 'number';
        const hasPriceMax = typeof filters.priceMax === 'number';

        if (hasPriceMin || hasPriceMax) {
            const amountFilter: Prisma.DecimalFilter = {};

            if (hasPriceMin) {
                amountFilter.gte = filters.priceMin;
            }

            if (hasPriceMax) {
                amountFilter.lte = filters.priceMax;
            }

            where.variants = {
                some: {
                    prices: {
                        some: {
                            amount: amountFilter,
                        },
                    },
                },
            };
        }

        return where;
    }

    private extractKeyFromUrl(url: string): string | null {
        try {
            const parsed = new URL(url);
            const pathname = decodeURIComponent(parsed.pathname);
            return pathname.replace(/^\/+/, '');
        } catch {
            return null;
        }
    }
}
