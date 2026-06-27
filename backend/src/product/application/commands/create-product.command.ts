import { CreateProductDto } from '../../presentation/dto';

export class CreateProductCommand {
    constructor(public readonly dto: CreateProductDto) {}
}
