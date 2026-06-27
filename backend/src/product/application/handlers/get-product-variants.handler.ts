import { Inject, Injectable } from '@nestjs/common';
import { ResponseVariantDto } from '../../presentation/dto';
import { GetProductVariantsQuery } from '../queries';
import { PRODUCT_VARIANT_REPOSITORY } from '../../product.tokens';
import type { IProductVariantRepository } from '../../domain/interfaces';

@Injectable()
export class GetProductVariantsHandler {
    constructor(
        @Inject(PRODUCT_VARIANT_REPOSITORY)
        private readonly productVariantRepository: IProductVariantRepository,
    ) {}

    async execute(
        query: GetProductVariantsQuery,
    ): Promise<ResponseVariantDto[]> {
        return this.productVariantRepository.findByProductId(
            query.productId,
        ) as unknown as ResponseVariantDto[];
    }
}
