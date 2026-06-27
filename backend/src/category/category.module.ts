import { Module } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthModule } from '../auth/auth.module';
import { CategoryController } from './presentation/controllers/category.controller';
import { CATEGORY_REPOSITORY } from './category.tokens';
import { PrismaCategoryRepository } from './infrastructure/repositories';
import {
    CreateCategoryHandler,
    DeleteCategoryHandler,
    GetCategoryByIdHandler,
    GetCategoryBySlugHandler,
    ListCategoriesHandler,
    UpdateCategoryHandler,
} from './application';

@Module({
    imports: [AuthModule],
    providers: [
        ListCategoriesHandler,
        GetCategoryByIdHandler,
        GetCategoryBySlugHandler,
        CreateCategoryHandler,
        UpdateCategoryHandler,
        DeleteCategoryHandler,
        {
            provide: CATEGORY_REPOSITORY,
            useClass: PrismaCategoryRepository,
        },
        PrismaService,
    ],
    controllers: [CategoryController],
    exports: [CATEGORY_REPOSITORY],
})
export class CategoryModule {}
