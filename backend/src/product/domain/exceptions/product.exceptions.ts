import { DomainException } from '../../../common/exceptions';

export class ProductNotFoundException extends DomainException {
    constructor(message: string = 'Product not found') {
        super('PRODUCT_NOT_FOUND', 404, message);
    }
}

export class ProductCategoryNotFoundException extends DomainException {
    constructor(message: string = 'Category not found') {
        super('PRODUCT_CATEGORY_NOT_FOUND', 404, message);
    }
}

export class ProductVariantNotFoundException extends DomainException {
    constructor(message: string = 'Product variant not found') {
        super('PRODUCT_VARIANT_NOT_FOUND', 404, message);
    }
}

export class ProductImageNotFoundException extends DomainException {
    constructor(message: string = 'Product image not found') {
        super('PRODUCT_IMAGE_NOT_FOUND', 404, message);
    }
}

export class ProductValidationException extends DomainException {
    constructor(message: string = 'Invalid product input') {
        super('PRODUCT_VALIDATION_FAILED', 400, message);
    }
}

export class ProductForbiddenException extends DomainException {
    constructor(message: string = 'Operation is forbidden for this product') {
        super('PRODUCT_FORBIDDEN', 403, message);
    }
}
