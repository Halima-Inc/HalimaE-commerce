import { Inject, Injectable } from '@nestjs/common';
import { CATEGORY_REPOSITORY } from '../../category.tokens';
import {
    CircularCategoryReferenceException,
    InvalidCategoryParentException,
} from '../../domain/exceptions';
import type { ICategoryRepository } from '../../domain/interfaces';
import { CreateCategoryCommand } from '../commands';
import { ResponseCategoryDto } from '../../presentation/dto';

@Injectable()
export class CreateCategoryHandler {
    constructor(
        @Inject(CATEGORY_REPOSITORY)
        private readonly categoryRepository: ICategoryRepository,
    ) {}

    async execute(
        command: CreateCategoryCommand,
    ): Promise<ResponseCategoryDto> {
        const { dto } = command;

        await this.ensureValidParent(dto.parentId ?? undefined, undefined);

        return this.categoryRepository.create({
            name: dto.name,
            slug: dto.slug,
            parentId: dto.parentId,
        });
    }

    private async ensureValidParent(
        parentId?: string,
        currentCategoryId?: string,
    ): Promise<void> {
        if (!parentId) {
            return;
        }

        if (currentCategoryId && parentId === currentCategoryId) {
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

        if (currentCategoryId) {
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
}
