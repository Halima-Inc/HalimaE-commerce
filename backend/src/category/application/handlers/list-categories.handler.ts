import { Inject, Injectable } from '@nestjs/common';
import { CATEGORY_REPOSITORY } from '../../category.tokens';
import type { ICategoryRepository } from '../../domain/interfaces';
import { ListCategoriesQuery } from '../queries';
import { ResponseCategoriesFilteredDto } from '../../presentation/dto';

@Injectable()
export class ListCategoriesHandler {
    constructor(
        @Inject(CATEGORY_REPOSITORY)
        private readonly categoryRepository: ICategoryRepository,
    ) {}

    async execute(
        input: ListCategoriesQuery,
    ): Promise<ResponseCategoriesFilteredDto> {
        const { totalCategories, categories } =
            await this.categoryRepository.findPaged(input);

        return {
            categories,
            meta: {
                totalCategories,
                totalPages: Math.ceil(totalCategories / input.limit),
                currentPage: input.page,
            },
        };
    }
}
