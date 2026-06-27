import { UpdateProductDto } from '../../presentation/dto';

export class UpdateProductCommand {
    constructor(
        public readonly id: string,
        public readonly dto: UpdateProductDto,
    ) {}
}
