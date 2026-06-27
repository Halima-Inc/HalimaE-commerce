export class CreateProductImageUploadUrlCommand {
    constructor(
        public readonly productId: string,
        public readonly contentType: string,
    ) {}
}
