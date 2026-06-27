import { Inject, Injectable } from '@nestjs/common';
import { ResponseVariantDto } from '../../presentation/dto';
import { CreateProductVariantCommand } from '../commands';
import { PRODUCT_VARIANT_REPOSITORY } from '../../product.tokens';
import type { IProductVariantRepository } from '../../domain/interfaces';

@Injectable()
export class CreateProductVariantHandler {
    constructor(
        @Inject(PRODUCT_VARIANT_REPOSITORY)
        private readonly productVariantRepository: IProductVariantRepository,
    ) {}

    async execute(
        command: CreateProductVariantCommand,
    ): Promise<ResponseVariantDto> {
        return this.productVariantRepository.create(
            command.productId,
            command.dto,
        ) as unknown as ResponseVariantDto;
    }
}
