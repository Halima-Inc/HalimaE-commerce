import { Inject, Injectable } from '@nestjs/common';
import { CATEGORY_REPOSITORY } from '../../category.tokens';
import {
    CategoryNotFoundException,
    CircularCategoryReferenceException,
    InvalidCategoryParentException,
} from '../../domain/exceptions';
import type { ICategoryRepository } from '../../domain/interfaces';
import { UpdateCategoryCommand } from '../commands';
import { ResponseCategoryDto } from '../../presentation/dto';

@Injectable()
export class UpdateCategoryHandler {
    constructor(
        @Inject(CATEGORY_REPOSITORY)
        private readonly categoryRepository: ICategoryRepository,
    ) {}

    async execute(
        command: UpdateCategoryCommand,
    ): Promise<ResponseCategoryDto> {
        const existingCategory = await this.categoryRepository.findById(
            command.id,
        );

        if (!existingCategory) {
            throw new CategoryNotFoundException(
                `Category with ID ${command.id} not found`,
            );
        }

        await this.ensureValidParent(
            command.dto.parentId ?? undefined,
            command.id,
        );

        const updatedCategory = await this.categoryRepository.update(
            command.id,
            {
                name: command.dto.name,
                slug: command.dto.slug,
                parentId: command.dto.parentId,
            },
        );

        if (!updatedCategory) {
            throw new CategoryNotFoundException(
                `Category with ID ${command.id} not found`,
            );
        }

        return updatedCategory;
    }

    private async ensureValidParent(
        parentId?: string,
        currentCategoryId?: string,
    ): Promise<void> {
        if (!parentId) {
            return;
        }

        if (parentId === currentCategoryId) {
            throw new InvalidCategoryParentException(
                'A category cannot be its own parent.',
            );
        }

        const parent = await this.categoryRepository.findById(parentId);
        if (!parent) {
            throw new InvalidCategoryParentException(
                `Parent category with ID ${parentId} does not exist.`,
            );
        }

        let ancestor = parent;
        while (ancestor.parentId) {
            if (ancestor.parentId === currentCategoryId) {
                throw new CircularCategoryReferenceException();
            }

            const nextAncestor = await this.categoryRepository.findById(
                ancestor.parentId,
            );

            if (!nextAncestor) {
                break;
            }

            ancestor = nextAncestor;
        }
    }
}
