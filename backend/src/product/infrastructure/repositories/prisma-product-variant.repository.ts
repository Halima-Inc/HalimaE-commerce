import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { LogService } from '../../../common/log.service';
import type {
    IProductVariantRepository,
    ProductVariantCreateInput,
    ProductVariantRecord,
    ProductVariantUpdateInput,
} from '../../domain/interfaces';
import {
    ProductForbiddenException,
    ProductValidationException,
    ProductVariantNotFoundException,
} from '../../domain/exceptions';

@Injectable()
export class PrismaProductVariantRepository
    implements IProductVariantRepository
{
    constructor(
        private readonly prisma: PrismaService,
        private readonly logger: LogService,
    ) {}

    async create(
        productId: string,
        variant: ProductVariantCreateInput,
    ): Promise<ProductVariantRecord> {
        this.logger.debug(
            `Creating variant for product ${productId}`,
            PrismaProductVariantRepository.name,
        );

        if (!Array.isArray(variant.prices) || variant.prices.length === 0) {
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

        const created = await this.prisma.productVariant.create({
            data: {
                sku: variant.sku,
                size: variant.size,
                color: variant.color,
                material: variant.material,
                isActive: variant.isActive ?? true,
                product: {
                    connect: { id: productId },
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
            include: {
                prices: {
                    select: {
                        id: true,
                        currency: true,
                        amount: true,
                        compareAt: true,
                    },
                },
                inventory: { select: { id: true, stockOnHand: true } },
            },
        });

        if (!created.inventory) {
            throw new ProductValidationException(
                'Failed to create variant inventory',
            );
        }

        return {
            id: created.id,
            productId,
            sku: created.sku,
            size: created.size,
            color: created.color,
            material: created.material,
            isActive: created.isActive,
            prices: created.prices.map((price) => ({
                id: price.id,
                currency: price.currency,
                amount: price.amount,
                compareAt: price.compareAt,
            })),
            inventory: {
                id: created.inventory.id,
                stockOnHand: created.inventory.stockOnHand,
            },
        };
    }

    async update(
        productId: string,
        id: string,
        variant: ProductVariantUpdateInput,
    ): Promise<ProductVariantRecord> {
        const existing = await this.prisma.productVariant.findUnique({
            where: { id },
            select: { productId: true },
        });

        if (!existing) {
            throw new ProductVariantNotFoundException(
                `Variant with ID ${id} not found`,
            );
        }

        if (existing.productId !== productId) {
            throw new ProductForbiddenException(
                `Variant with ID ${id} does not belong to product with ID ${productId}`,
            );
        }

        const updated = await this.prisma.productVariant.update({
            where: { id },
            data: {
                sku: variant.sku,
                size: variant.size,
                material: variant.material,
                color: variant.color,
                isActive: variant.isActive ?? true,
                prices: {
                    upsert: variant.prices?.map((price) => ({
                        where: { id: price.id ?? '' },
                        update: {
                            ...(price.currency && { currency: price.currency }),
                            ...(price.amount !== undefined && {
                                amount: price.amount,
                            }),
                            ...(price.compareAt !== undefined && {
                                compareAt: price.compareAt,
                            }),
                        },
                        create: {
                            currency: price.currency!,
                            amount: price.amount!,
                            compareAt: price.compareAt ?? null,
                        },
                    })),
                },
                inventory: variant.inventory
                    ? {
                          upsert: {
                              update: {
                                  stockOnHand: variant.inventory.stockOnHand,
                              },
                              create: {
                                  stockOnHand: variant.inventory.stockOnHand,
                              },
                          },
                      }
                    : undefined,
            },
            include: {
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
        });

        if (!updated.inventory) {
            throw new ProductValidationException('Variant inventory not found');
        }

        return {
            id: updated.id,
            productId,
            sku: updated.sku,
            size: updated.size,
            color: updated.color,
            material: updated.material,
            isActive: updated.isActive,
            prices: updated.prices.map((price) => ({
                id: price.id,
                currency: price.currency,
                amount: price.amount,
                compareAt: price.compareAt,
            })),
            inventory: {
                id: updated.inventory.id,
                stockOnHand: updated.inventory.stockOnHand,
            },
        };
    }

    async findByProductId(productId: string): Promise<ProductVariantRecord[]> {
        const variants = await this.prisma.productVariant.findMany({
            where: { productId },
            select: {
                id: true,
                productId: true,
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
        });

        if (!variants.length) {
            throw new ProductVariantNotFoundException(
                `product with id ${productId} has no variants`,
            );
        }

        const missingInventory = variants.filter(
            (variant) => !variant.inventory,
        );
        if (missingInventory.length > 0) {
            throw new ProductValidationException(
                'Some variants are missing inventory data',
            );
        }

        return variants.map((variant) => ({
            id: variant.id,
            productId: variant.productId,
            sku: variant.sku,
            size: variant.size,
            color: variant.color,
            material: variant.material,
            isActive: variant.isActive,
            prices: variant.prices.map((price) => ({
                id: price.id,
                currency: price.currency,
                amount: price.amount,
                compareAt: price.compareAt,
            })),
            inventory: {
                id: variant.inventory!.id,
                stockOnHand: variant.inventory!.stockOnHand,
            },
        }));
    }

    async delete(productId: string, id: string): Promise<void> {
        const variant = await this.prisma.productVariant.findUnique({
            where: { id },
            select: { productId: true },
        });

        if (!variant) {
            throw new ProductVariantNotFoundException(
                `Variant with ID ${id} not found`,
            );
        }

        if (variant.productId !== productId) {
            throw new ProductForbiddenException(
                `Variant with ID ${id} does not belong to product with ID ${productId}`,
            );
        }

        await this.prisma.$transaction(async (tx) => {
            await tx.variantPrice.deleteMany({ where: { variantId: id } });
            await tx.variantInventory.deleteMany({ where: { variantId: id } });
            await tx.productVariant.delete({ where: { id } });
        });
    }

    async findById(id: string): Promise<{
        id: string;
        sku: string;
        isActive: boolean;
        product: { name: string };
        inventory: { stockOnHand: number };
    }> {
        const variant = await this.prisma.productVariant.findUnique({
            where: { id },
            select: {
                id: true,
                sku: true,
                isActive: true,
                product: {
                    select: {
                        name: true,
                    },
                },
                inventory: {
                    select: {
                        stockOnHand: true,
                    },
                },
            },
        });

        if (!variant) {
            throw new ProductValidationException('Product variant not found');
        }

        if (!variant.isActive) {
            throw new ProductValidationException(
                `Product "${variant.product.name}" is no longer available`,
            );
        }

        if (!variant.inventory) {
            throw new ProductValidationException(
                `Product inventory not found for variant ${id}`,
            );
        }

        return {
            id: variant.id,
            sku: variant.sku,
            isActive: variant.isActive,
            product: {
                name: variant.product.name,
            },
            inventory: {
                stockOnHand: variant.inventory.stockOnHand,
            },
        };
    }

    async updateInventory(
        variantId: string,
        operation: 'increment' | 'decrement',
        quantity = 1,
    ): Promise<void> {
        const inventory = await this.prisma.variantInventory.findUnique({
            where: { variantId },
            select: { id: true },
        });

        if (!inventory) {
            throw new ProductValidationException(
                `Variant inventory not found for ${variantId}`,
            );
        }

        if (operation === 'decrement') {
            const result = await this.prisma.variantInventory.updateMany({
                where: {
                    id: inventory.id,
                    stockOnHand: { gte: quantity },
                },
                data: {
                    stockOnHand: {
                        decrement: quantity,
                    },
                },
            });

            if (result.count === 0) {
                throw new ProductValidationException(
                    `Insufficient stock. Cannot reduce inventory by ${quantity}.`,
                );
            }

            return;
        }

        await this.prisma.variantInventory.update({
            where: { id: inventory.id },
            data: {
                stockOnHand: {
                    increment: quantity,
                },
            },
        });
    }
}
