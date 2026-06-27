import { ProductVariantDto } from '../../presentation/dto';

export class CreateProductVariantCommand {
    constructor(
        public readonly productId: string,
        public readonly dto: ProductVariantDto,
    ) {}
}
