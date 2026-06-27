import type { Category } from '../entities';

export type FindCategoriesInput = {
    page: number;
    limit: number;
    orderBy: 'name' | 'slug';
    orderDirection: 'asc' | 'desc';
    search?: string;
};

export type FindCategoriesResult = {
    totalCategories: number;
    categories: Category[];
};

export interface ICategoryRepository {
    findPaged(input: FindCategoriesInput): Promise<FindCategoriesResult>;

    findById(id: string): Promise<Category | null>;

    findBySlug(slug: string): Promise<Category | null>;

    existsById(id: string): Promise<boolean>;

    create(data: {
        name: string;
        slug: string;
        parentId?: string | null;
    }): Promise<Category>;

    update(
        id: string,
        data: {
            name?: string;
            slug?: string;
            parentId?: string | null;
        },
    ): Promise<Category | null>;

    hasChildren(id: string): Promise<boolean>;

    deleteById(id: string): Promise<boolean>;
}
