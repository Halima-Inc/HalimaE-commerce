import { FilterProductDto } from '../../presentation/dto';

export class ListProductsQuery {
    constructor(public readonly filters: FilterProductDto) {}
}

export class GetProductByIdQuery {
    constructor(public readonly id: string) {}
}
