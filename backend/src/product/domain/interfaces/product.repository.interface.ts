import { Status } from '@prisma/client';
import type { Product } from '../entities';
import type { ProductVariantCreateInput } from './product-variant.repository.interface';

export type ProductListFilters = {
    page: number;
    pageSize: number;
    name?: string;
    categoryId?: string;
    status?: Status;
    priceMin?: number;
    priceMax?: number;
};

export type ProductDeleteSnapshot = {
    id: string;
    images: Array<{
        id: string;
        alt: string | null;
        url: string;
    }>;
    variants: Array<{
        id: string;
    }>;
};

export type CreateProductAggregateInput = {
    name: string;
    slug: string;
    description?: string | null;
    status: Status;
    categoryId: string;
    variants: ProductVariantCreateInput[];
};

export interface IProductRepository {
    findPaged(filters: ProductListFilters): Promise<{
        totalProducts: number;
        products: Product[];
    }>;

    findById(id: string): Promise<Product | null>;

    updateById(
        id: string,
        data: {
            name?: string;
            slug?: string;
            description?: string | null;
            status?: Status;
            categoryId?: string;
        },
    ): Promise<Product>;

    createWithVariants(
        input: CreateProductAggregateInput,
    ): Promise<Product | null>;

    deleteWithRelations(id: string): Promise<void>;

    existsById(id: string): Promise<boolean>;
}
