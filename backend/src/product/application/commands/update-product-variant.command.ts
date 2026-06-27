import { UpdateVariantDto } from '../../presentation/dto';

export class UpdateProductVariantCommand {
    constructor(
        public readonly productId: string,
        public readonly variantId: string,
        public readonly dto: UpdateVariantDto,
    ) {}
}
