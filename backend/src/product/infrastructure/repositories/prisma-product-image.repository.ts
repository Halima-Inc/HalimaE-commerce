import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import type {
    IProductImageRepository,
    ProductImageCreateInput,
    ProductImageRecord,
    ProductImageReplaceInput,
} from '../../domain/interfaces';
import {
    ProductForbiddenException,
    ProductImageNotFoundException,
    ProductNotFoundException,
} from '../../domain/exceptions';

@Injectable()
export class PrismaProductImageRepository implements IProductImageRepository {
    constructor(private readonly prisma: PrismaService) {}

    async create(
        productId: string,
        input: ProductImageCreateInput,
    ): Promise<ProductImageRecord> {
        await this.ensureProductExists(productId);

        const created = await this.prisma.productImage.create({
            data: {
                productId,
                url: input.url,
                alt: input.alt ?? null,
                sort: input.sort ?? 0,
            },
        });

        return created;
    }

    async findByProductId(productId: string): Promise<ProductImageRecord[]> {
        return this.prisma.productImage.findMany({
            where: { productId },
            orderBy: { sort: 'asc' },
        });
    }

    async replace(
        productId: string,
        id: string,
        input: ProductImageReplaceInput,
    ): Promise<{ updated: ProductImageRecord; previousUrl: string }> {
        const image = await this.prisma.productImage.findUnique({
            where: { id },
            select: {
                id: true,
                url: true,
                alt: true,
                productId: true,
            },
        });

        if (!image) {
            throw new ProductImageNotFoundException(
                `Image with ID ${id} not found.`,
            );
        }

        if (image.productId !== productId) {
            throw new ProductForbiddenException(
                `Image with ID ${id} does not belong to product with ID ${productId}`,
            );
        }

        const updated = await this.prisma.productImage.update({
            where: { id },
            data: {
                url: input.url,
                alt: input.alt ?? image.alt,
                sort: input.sort,
            },
        });

        return {
            updated,
            previousUrl: image.url,
        };
    }

    async delete(
        productId: string,
        id: string,
    ): Promise<{ deletedUrl: string }> {
        const image = await this.prisma.productImage.findUnique({
            where: { id },
            select: { productId: true, url: true },
        });

        if (!image) {
            throw new ProductImageNotFoundException(
                `Image with ID ${id} not found.`,
            );
        }

        if (image.productId !== productId) {
            throw new ProductForbiddenException(
                'You are not allowed to delete this image.',
            );
        }

        await this.prisma.productImage.delete({ where: { id } });

        return {
            deletedUrl: image.url,
        };
    }

    private async ensureProductExists(productId: string): Promise<void> {
        const product = await this.prisma.product.findUnique({
            where: { id: productId },
            select: { id: true },
        });

        if (!product) {
            throw new ProductNotFoundException(
                `Product with ID ${productId} not found.`,
            );
        }
    }
}
