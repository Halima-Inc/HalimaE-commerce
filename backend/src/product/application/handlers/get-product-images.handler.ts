import { Inject, Injectable } from '@nestjs/common';
import { GetProductImagesQuery } from '../queries';
import { PRODUCT_IMAGE_REPOSITORY } from '../../product.tokens';
import type {
    IProductImageRepository,
    ProductImageRecord,
} from '../../domain/interfaces';

@Injectable()
export class GetProductImagesHandler {
    constructor(
        @Inject(PRODUCT_IMAGE_REPOSITORY)
        private readonly productImageRepository: IProductImageRepository,
    ) {}

    async execute(query: GetProductImagesQuery): Promise<ProductImageRecord[]> {
        return this.productImageRepository.findByProductId(query.productId);
    }
}
