import { Inject, Injectable } from '@nestjs/common';
import { DeleteProductVariantCommand } from '../commands';
import { PRODUCT_VARIANT_REPOSITORY } from '../../product.tokens';
import type { IProductVariantRepository } from '../../domain/interfaces';

@Injectable()
export class DeleteProductVariantHandler {
    constructor(
        @Inject(PRODUCT_VARIANT_REPOSITORY)
        private readonly productVariantRepository: IProductVariantRepository,
    ) {}

    async execute(command: DeleteProductVariantCommand): Promise<void> {
        await this.productVariantRepository.delete(
            command.productId,
            command.variantId,
        );
    }
}
