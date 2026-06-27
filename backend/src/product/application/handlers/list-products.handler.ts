import { Inject, Injectable } from '@nestjs/common';
import {
    ResponseProductDto,
    ResponseProductFilteredDto,
} from '../../presentation/dto';
import { PRODUCT_REPOSITORY } from '../../product.tokens';
import type { IProductRepository } from '../../domain/interfaces';
import { ListProductsQuery } from '../queries';

@Injectable()
export class ListProductsHandler {
    constructor(
        @Inject(PRODUCT_REPOSITORY)
        private readonly productRepository: IProductRepository,
    ) {}

    async execute(
        query: ListProductsQuery,
    ): Promise<ResponseProductFilteredDto> {
        const filters = query.filters;
        const page =
            Number.isFinite(filters.page) && filters.page > 0
                ? Math.floor(filters.page)
                : 1;
        const pageSize = 12;
        const normalizedName = filters.name?.trim() || undefined;
        const normalizedCategoryId = filters.categoryId?.trim() || undefined;
        const normalizedPriceMin =
            typeof filters.priceMin === 'number' &&
            Number.isFinite(filters.priceMin)
                ? Math.max(0, filters.priceMin)
                : 0;
        const normalizedPriceMax =
            typeof filters.priceMax === 'number' &&
            Number.isFinite(filters.priceMax)
                ? filters.priceMax
                : undefined;

        const { totalProducts, products } =
            await this.productRepository.findPaged({
                page,
                pageSize,
                name: normalizedName,
                categoryId: normalizedCategoryId,
                status: filters.status,
                priceMin: normalizedPriceMin,
                priceMax: normalizedPriceMax,
            });

        return {
            products: products as unknown as ResponseProductDto[],
            meta: {
                totalPages: Math.ceil(totalProducts / pageSize),
                currentPage: page,
                totalProducts,
            },
        };
    }
}
