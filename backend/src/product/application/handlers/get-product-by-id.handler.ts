import { Inject, Injectable } from '@nestjs/common';
import { ResponseProductDto } from '../../presentation/dto';
import { PRODUCT_REPOSITORY } from '../../product.tokens';
import type { IProductRepository } from '../../domain/interfaces';
import { ProductNotFoundException } from '../../domain/exceptions';
import { GetProductByIdQuery } from '../queries';

@Injectable()
export class GetProductByIdHandler {
    constructor(
        @Inject(PRODUCT_REPOSITORY)
        private readonly productRepository: IProductRepository,
    ) {}

    async execute(query: GetProductByIdQuery): Promise<ResponseProductDto> {
        const product = await this.productRepository.findById(query.id);

        if (!product) {
            throw new ProductNotFoundException(
                `Product with ID ${query.id} not found`,
            );
        }

        return product as unknown as ResponseProductDto;
    }
}
