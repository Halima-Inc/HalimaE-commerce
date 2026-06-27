import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import type {
    FindCategoriesInput,
    FindCategoriesResult,
    ICategoryRepository,
} from '../../domain/interfaces';
import { Category, type CategoryRecord } from '../../domain/entities';

function mapCategoryRecord(record: CategoryRecord): Category {
    return Category.create(record);
}

@Injectable()
export class PrismaCategoryRepository implements ICategoryRepository {
    constructor(private readonly prisma: PrismaService) {}

    async findPaged(input: FindCategoriesInput): Promise<FindCategoriesResult> {
        const where = input.search
            ? {
                  name: {
                      contains: input.search,
                      mode: 'insensitive' as const,
                  },
              }
            : {};

        const [totalCategories, categories] = await this.prisma.$transaction([
            this.prisma.category.count({ where }),
            this.prisma.category.findMany({
                skip: (input.page - 1) * input.limit,
                take: input.limit,
                orderBy: {
                    [input.orderBy]: input.orderDirection,
                },
                where,
                select: {
                    id: true,
                    name: true,
                    slug: true,
                    parentId: true,
                    parent: {
                        select: {
                            id: true,
                            name: true,
                            slug: true,
                            parentId: true,
                        },
                    },
                },
            }),
        ]);

        return {
            totalCategories,
            categories: categories.map((category) =>
                mapCategoryRecord(category),
            ),
        };
    }

    async findById(id: string): Promise<Category | null> {
        const category = await this.prisma.category.findUnique({
            where: { id },
            select: {
                id: true,
                name: true,
                slug: true,
                parentId: true,
                parent: {
                    select: {
                        id: true,
                        name: true,
                        slug: true,
                        parentId: true,
                    },
                },
            },
        });

        return category ? mapCategoryRecord(category) : null;
    }

    async findBySlug(slug: string): Promise<Category | null> {
        const category = await this.prisma.category.findUnique({
            where: { slug },
            select: {
                id: true,
                name: true,
                slug: true,
                parentId: true,
                parent: {
                    select: {
                        id: true,
                        name: true,
                        slug: true,
                        parentId: true,
                    },
                },
            },
        });

        return category ? mapCategoryRecord(category) : null;
    }

    async existsById(id: string): Promise<boolean> {
        const category = await this.prisma.category.findUnique({
            where: { id },
            select: { id: true },
        });

        return Boolean(category);
    }

    async create(data: {
        name: string;
        slug: string;
        parentId?: string | null;
    }): Promise<Category> {
        const category = await this.prisma.category.create({
            data: {
                name: data.name,
                slug: data.slug,
                parent: data.parentId
                    ? {
                          connect: {
                              id: data.parentId,
                          },
                      }
                    : undefined,
            },
            select: {
                id: true,
                name: true,
                slug: true,
                parentId: true,
                parent: {
                    select: {
                        id: true,
                        name: true,
                        slug: true,
                        parentId: true,
                    },
                },
            },
        });

        return mapCategoryRecord(category);
    }

    async update(
        id: string,
        data: {
            name?: string;
            slug?: string;
            parentId?: string | null;
        },
    ): Promise<Category | null> {
        try {
            const category = await this.prisma.category.update({
                where: { id },
                data: {
                    name: data.name,
                    slug: data.slug,
                    parent:
                        data.parentId === undefined
                            ? undefined
                            : data.parentId === null
                              ? { disconnect: true }
                              : {
                                    connect: {
                                        id: data.parentId,
                                    },
                                },
                },
                select: {
                    id: true,
                    name: true,
                    slug: true,
                    parentId: true,
                    parent: {
                        select: {
                            id: true,
                            name: true,
                            slug: true,
                            parentId: true,
                        },
                    },
                },
            });

            return mapCategoryRecord(category);
        } catch {
            return null;
        }
    }

    async hasChildren(id: string): Promise<boolean> {
        const subCategories = await this.prisma.category.findFirst({
            where: { parentId: id },
            select: { id: true },
        });

        return Boolean(subCategories);
    }

    async deleteById(id: string): Promise<boolean> {
        try {
            await this.prisma.category.delete({
                where: { id },
            });
            return true;
        } catch {
            return false;
        }
    }
}
