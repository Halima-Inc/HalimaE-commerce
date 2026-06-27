export class DeleteProductVariantCommand {
    constructor(
        public readonly productId: string,
        public readonly variantId: string,
    ) {}
}
