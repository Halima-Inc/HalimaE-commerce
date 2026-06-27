import { CreateCategoryDto, UpdateCategoryDto } from '../../presentation/dto';

export class CreateCategoryCommand {
    constructor(public readonly dto: CreateCategoryDto) {}
}

export class UpdateCategoryCommand {
    constructor(
        public readonly id: string,
        public readonly dto: UpdateCategoryDto,
    ) {}
}

export class DeleteCategoryCommand {
    constructor(public readonly id: string) {}
}
