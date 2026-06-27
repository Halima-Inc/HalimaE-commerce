import { Inject, Injectable } from '@nestjs/common';
import { CATEGORY_REPOSITORY } from '../../../category/category.tokens';
import type { ICategoryRepository } from '../../../category/domain/interfaces';
import { ResponseProductDto } from '../../presentation/dto';
import { UpdateProductCommand } from '../commands';
import { PRODUCT_REPOSITORY } from '../../product.tokens';
import type { IProductRepository } from '../../domain/interfaces';
import type { Product } from '../../domain/entities';
import {
    ProductCategoryNotFoundException,
    ProductNotFoundException,
    ProductValidationException,
} from '../../domain/exceptions';

@Injectable()
export class UpdateProductHandler {
    constructor(
        @Inject(PRODUCT_REPOSITORY)
        private readonly productRepository: IProductRepository,
        @Inject(CATEGORY_REPOSITORY)
        private readonly categoryRepository: ICategoryRepository,
    ) {}

    async execute(command: UpdateProductCommand): Promise<ResponseProductDto> {
        if (command.dto.categoryId) {
            await this.ensureCategoryExists(command.dto.categoryId);
        }

        const existingProduct = await this.productRepository.findById(
            command.id,
        );
        if (!existingProduct) {
            throw new ProductNotFoundException(
                `Product with ID ${command.id} not found.`,
            );
        }

        const updatedProduct = await this.productRepository.updateById(
            command.id,
            {
                name: command.dto.name,
                slug: command.dto.slug,
                description: command.dto.description,
                status: command.dto.status,
                categoryId: command.dto.categoryId,
            },
        );

        this.assertProductVariantsHaveInventory(updatedProduct);
        return updatedProduct as unknown as ResponseProductDto;
    }

    private async ensureCategoryExists(categoryId: string): Promise<void> {
        const exists = await this.categoryRepository.existsById(categoryId);

        if (!exists) {
            throw new ProductCategoryNotFoundException(
                `Category with ID ${categoryId} not found.`,
            );
        }
    }

    private assertProductVariantsHaveInventory(product: Product): void {
        const variantsWithoutInventory =
            product.variants?.filter((variant) => !variant.inventory) ?? [];

        if (variantsWithoutInventory.length > 0) {
            throw new ProductValidationException(
                'Some variants are missing inventory data',
            );
        }
    }
}
