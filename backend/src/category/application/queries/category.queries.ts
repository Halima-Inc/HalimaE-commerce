import { FindCategoriesInput } from '../../domain/interfaces';

export type ListCategoriesQuery = FindCategoriesInput;

export class GetCategoryByIdQuery {
    constructor(public readonly id: string) {}
}

export class GetCategoryBySlugQuery {
    constructor(public readonly slug: string) {}
}
