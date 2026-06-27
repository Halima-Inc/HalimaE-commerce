import { Prisma, Status } from '@prisma/client';

export type ProductImage = {
    id: string;
    productId?: string;
    url: string;
    alt?: string | null;
    sort?: number;
};

export type VariantPrice = {
    id: string;
    compareAt: Prisma.Decimal | null;
    amount: Prisma.Decimal;
    currency: string;
};

export type VariantInventory = {
    id: string;
    stockOnHand: number;
};

export type ProductVariant = {
    id: string;
    sku: string;
    size: string | null;
    color: string | null;
    material: string | null;
    isActive: boolean;
    prices: VariantPrice[];
    inventory: VariantInventory | null;
    productId?: string;
};

export type ProductRecord = {
    id: string;
    name: string;
    slug: string;
    description: string | null;
    status: Status;
    categoryId: string;
    createdAt: Date;
    updatedAt: Date;
    images: ProductImage[];
    variants: ProductVariant[];
};

export class Product {
    constructor(
        public readonly id: string,
        public readonly name: string,
        public readonly slug: string,
        public readonly description: string | null,
        public readonly status: Status,
        public readonly categoryId: string,
        public readonly createdAt: Date,
        public readonly updatedAt: Date,
        public readonly images: ProductImage[],
        public readonly variants: ProductVariant[],
    ) {}

    static create(record: ProductRecord): Product {
        return new Product(
            record.id,
            record.name,
            record.slug,
            record.description,
            record.status,
            record.categoryId,
            record.createdAt,
            record.updatedAt,
            record.images,
            record.variants,
        );
    }

    hasVariants(): boolean {
        return this.variants.length > 0;
    }

    hasImages(): boolean {
        return this.images.length > 0;
    }
}
