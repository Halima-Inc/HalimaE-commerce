import { Inject, Injectable } from '@nestjs/common';
import { ResponseVariantDto } from '../../presentation/dto';
import { UpdateProductVariantCommand } from '../commands';
import { PRODUCT_VARIANT_REPOSITORY } from '../../product.tokens';
import type { IProductVariantRepository } from '../../domain/interfaces';

@Injectable()
export class UpdateProductVariantHandler {
    constructor(
        @Inject(PRODUCT_VARIANT_REPOSITORY)
        private readonly productVariantRepository: IProductVariantRepository,
    ) {}

    async execute(
        command: UpdateProductVariantCommand,
    ): Promise<ResponseVariantDto> {
        return this.productVariantRepository.update(
            command.productId,
            command.variantId,
            command.dto,
        ) as unknown as ResponseVariantDto;
    }
}
