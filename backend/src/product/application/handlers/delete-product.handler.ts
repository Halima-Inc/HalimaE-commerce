import { Inject, Injectable } from '@nestjs/common';
import { DeleteProductCommand } from '../commands';
import { PRODUCT_REPOSITORY } from '../../product.tokens';
import type { IProductRepository } from '../../domain/interfaces';

@Injectable()
export class DeleteProductHandler {
    constructor(
        @Inject(PRODUCT_REPOSITORY)
        private readonly productRepository: IProductRepository,
    ) {}

    async execute(command: DeleteProductCommand): Promise<void> {
        await this.productRepository.deleteWithRelations(command.id);
    }
}
