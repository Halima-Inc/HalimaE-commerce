import { Inject, Injectable } from '@nestjs/common';
import { CATEGORY_REPOSITORY } from '../../category.tokens';
import type { ICategoryRepository } from '../../domain/interfaces';
import { CategoryNotFoundException } from '../../domain/exceptions';
import { GetCategoryByIdQuery } from '../queries';
import { ResponseCategoryDto } from '../../presentation/dto';

@Injectable()
export class GetCategoryByIdHandler {
    constructor(
        @Inject(CATEGORY_REPOSITORY)
        private readonly categoryRepository: ICategoryRepository,
    ) {}

    async execute(query: GetCategoryByIdQuery): Promise<ResponseCategoryDto> {
        const category = await this.categoryRepository.findById(query.id);

        if (!category) {
            throw new CategoryNotFoundException(
                `Category with ID ${query.id} not found`,
            );
        }

        return category;
    }
}
