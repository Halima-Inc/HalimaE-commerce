import { DomainException } from './domain.exception';

export class CategoryNotFoundException extends DomainException {
    constructor(message: string = 'Category not found') {
        super('CATEGORY_NOT_FOUND', 404, message);
    }
}

export class InvalidCategoryParentException extends DomainException {
    constructor(message: string = 'Invalid parent category') {
        super('INVALID_CATEGORY_PARENT', 400, message);
    }
}

export class CircularCategoryReferenceException extends DomainException {
    constructor(message: string = 'Category hierarchy cannot contain cycles') {
        super('CIRCULAR_CATEGORY_REFERENCE', 409, message);
    }
}

export class CategoryHasChildrenException extends DomainException {
    constructor(message: string = 'Cannot delete category with subcategories') {
        super('CATEGORY_HAS_CHILDREN', 409, message);
    }
}
