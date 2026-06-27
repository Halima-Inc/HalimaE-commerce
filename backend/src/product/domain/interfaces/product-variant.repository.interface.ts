import { Prisma } from '@prisma/client';

export type ProductVariantPriceInput = {
    id?: string;
    currency?: string;
    amount?: Prisma.Decimal;
    compareAt?: Prisma.Decimal | null;
};

export type ProductVariantInventoryInput = {
    stockOnHand: number;
};

export type ProductVariantCreateInput = {
    sku: string;
    size?: string | null;
    color?: string | null;
    material?: string | null;
    isActive?: boolean | null;
    prices: ProductVariantPriceInput[];
    inventory: ProductVariantInventoryInput;
};

export type ProductVariantUpdateInput = {
    sku?: string;
    size?: string | null;
    color?: string | null;
    material?: string | null;
    isActive?: boolean | null;
    prices?: ProductVariantPriceInput[];
    inventory?: ProductVariantInventoryInput;
};

export type ProductVariantRecord = {
    id: string;
    productId: string;
    sku: string;
    size: string | null;
    color: string | null;
    material: string | null;
    isActive: boolean;
    prices: Array<{
        id: string;
        currency: string;
        amount: Prisma.Decimal;
        compareAt: Prisma.Decimal | null;
    }>;
    inventory: {
        id: string;
        stockOnHand: number;
    };
};

export interface IProductVariantRepository {
    create(
        productId: string,
        variant: ProductVariantCreateInput,
    ): Promise<ProductVariantRecord>;
    update(
        productId: string,
        id: string,
        variant: ProductVariantUpdateInput,
    ): Promise<ProductVariantRecord>;
    findByProductId(productId: string): Promise<ProductVariantRecord[]>;
    delete(productId: string, id: string): Promise<void>;
    findById(id: string): Promise<{
        id: string;
        sku: string;
        isActive: boolean;
        product: { name: string };
        inventory: { stockOnHand: number };
    }>;
    updateInventory(
        variantId: string,
        operation: 'increment' | 'decrement',
        quantity?: number,
    ): Promise<void>;
}
