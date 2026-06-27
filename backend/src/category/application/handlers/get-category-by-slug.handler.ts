import { Inject, Injectable } from '@nestjs/common';
import { CATEGORY_REPOSITORY } from '../../category.tokens';
import type { ICategoryRepository } from '../../domain/interfaces';
import { CategoryNotFoundException } from '../../domain/exceptions';
import { GetCategoryBySlugQuery } from '../queries';
import { ResponseCategoryDto } from '../../presentation/dto';

@Injectable()
export class GetCategoryBySlugHandler {
    constructor(
        @Inject(CATEGORY_REPOSITORY)
        private readonly categoryRepository: ICategoryRepository,
    ) {}

    async execute(query: GetCategoryBySlugQuery): Promise<ResponseCategoryDto> {
        const category = await this.categoryRepository.findBySlug(query.slug);

        if (!category) {
            throw new CategoryNotFoundException(
                `Category with slug ${query.slug} not found`,
            );
        }

        return category;
    }
}
