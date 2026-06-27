export class DeleteProductImageCommand {
    constructor(
        public readonly productId: string,
        public readonly imageId: string,
    ) {}
}
