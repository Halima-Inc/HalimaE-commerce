export type ProductImageRecord = {
    id: string;
    productId: string;
    url: string;
    alt: string | null;
    sort: number;
    createdAt?: Date;
    updatedAt?: Date;
};

export type ProductImageCreateInput = {
    url: string;
    alt?: string | null;
    sort?: number;
};

export type ProductImageReplaceInput = {
    url: string;
    alt?: string | null;
    sort?: number;
};

export interface IProductImageRepository {
    create(
        productId: string,
        input: ProductImageCreateInput,
    ): Promise<ProductImageRecord>;
    findByProductId(productId: string): Promise<ProductImageRecord[]>;
    replace(
        productId: string,
        id: string,
        input: ProductImageReplaceInput,
    ): Promise<{
        updated: ProductImageRecord;
        previousUrl: string;
    }>;
    delete(productId: string, id: string): Promise<{ deletedUrl: string }>;
}
