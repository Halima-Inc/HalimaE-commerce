import { FinalizeProductImageUploadDto } from '../../presentation/dto';

export class FinalizeProductImageUploadCommand {
    constructor(
        public readonly productId: string,
        public readonly dto: FinalizeProductImageUploadDto,
    ) {}
}
