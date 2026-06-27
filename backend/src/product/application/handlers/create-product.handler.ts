import { Inject, Injectable } from '@nestjs/common';
import { CATEGORY_REPOSITORY } from '../../../category/category.tokens';
import type { ICategoryRepository } from '../../../category/domain/interfaces';
import { ResponseProductDto } from '../../presentation/dto';
import { CreateProductCommand } from '../commands';
import { PRODUCT_REPOSITORY } from '../../product.tokens';
import type { IProductRepository } from '../../domain/interfaces';
import type { Product } from '../../domain/entities';
import {
    ProductCategoryNotFoundException,
    ProductValidationException,
} from '../../domain/exceptions';

@Injectable()
export class CreateProductHandler {
    constructor(
        @Inject(PRODUCT_REPOSITORY)
        private readonly productRepository: IProductRepository,
        @Inject(CATEGORY_REPOSITORY)
        private readonly categoryRepository: ICategoryRepository,
    ) {}

    async execute(
        command: CreateProductCommand,
    ): Promise<ResponseProductDto | null> {
        await this.ensureCategoryExists(command.dto.categoryId);

        const createdProduct = await this.productRepository.createWithVariants({
            name: command.dto.name,
            slug: command.dto.slug,
            description: command.dto.description,
            status: command.dto.status,
            categoryId: command.dto.categoryId,
            variants: command.dto.variants,
        });

        if (createdProduct) {
            this.assertProductVariantsHaveInventory(createdProduct);
        }

        return createdProduct as unknown as ResponseProductDto | null;
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
