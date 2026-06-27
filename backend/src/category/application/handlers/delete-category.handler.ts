import { Inject, Injectable } from '@nestjs/common';
import { CATEGORY_REPOSITORY } from '../../category.tokens';
import {
    CategoryHasChildrenException,
    CategoryNotFoundException,
} from '../../domain/exceptions';
import type { ICategoryRepository } from '../../domain/interfaces';
import { DeleteCategoryCommand } from '../commands';

@Injectable()
export class DeleteCategoryHandler {
    constructor(
        @Inject(CATEGORY_REPOSITORY)
        private readonly categoryRepository: ICategoryRepository,
    ) {}

    async execute(command: DeleteCategoryCommand): Promise<void> {
        const category = await this.categoryRepository.findById(command.id);

        if (!category) {
            throw new CategoryNotFoundException(
                `Category with ID ${command.id} not found`,
            );
        }

        const hasChildren = await this.categoryRepository.hasChildren(
            command.id,
        );
        if (hasChildren) {
            throw new CategoryHasChildrenException();
        }

        const deleted = await this.categoryRepository.deleteById(command.id);
        if (!deleted) {
            throw new CategoryNotFoundException(
                `Category with ID ${command.id} not found`,
            );
        }
    }
}
