import { FinalizeProductImageUploadDto } from '../../presentation/dto';

export class ReplaceProductImageCommand {
    constructor(
        public readonly productId: string,
        public readonly imageId: string,
        public readonly dto: FinalizeProductImageUploadDto,
    ) {}
}
