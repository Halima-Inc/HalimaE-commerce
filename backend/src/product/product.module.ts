import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { AuthModule } from '../auth/auth.module';
import { ProductController } from './presentation/controllers/product.controller';
import { S3StorageService } from './infrastructure/services/s3-storage.service';
import {
    PrismaProductImageRepository,
    PrismaProductRepository,
    PrismaProductVariantRepository,
} from './infrastructure/repositories';
import { CategoryModule } from '../category/category.module';
import {
    PRODUCT_IMAGE_REPOSITORY,
    PRODUCT_REPOSITORY,
    PRODUCT_VARIANT_REPOSITORY,
    STORAGE_SERVICE,
} from './product.tokens';
import {
    CreateProductImageUploadUrlHandler,
    CreateProductHandler,
    CreateProductVariantHandler,
    DeleteProductImageHandler,
    DeleteProductHandler,
    DeleteProductVariantHandler,
    FinalizeProductImageUploadHandler,
    GetProductByIdHandler,
    GetProductImagesHandler,
    GetProductVariantsHandler,
    ListProductsHandler,
    ReplaceProductImageHandler,
    UpdateProductHandler,
    UpdateProductVariantHandler,
} from './application';

@Module({
    imports: [ConfigModule, AuthModule, CategoryModule],
    controllers: [ProductController],
    providers: [
        PrismaService,

        // Infrastructure implementations
        PrismaProductVariantRepository,
        PrismaProductImageRepository,
        S3StorageService,

        // Use-case handlers
        ListProductsHandler,
        GetProductByIdHandler,
        CreateProductHandler,
        UpdateProductHandler,
        DeleteProductHandler,
        GetProductVariantsHandler,
        CreateProductVariantHandler,
        UpdateProductVariantHandler,
        DeleteProductVariantHandler,
        GetProductImagesHandler,
        CreateProductImageUploadUrlHandler,
        FinalizeProductImageUploadHandler,
        ReplaceProductImageHandler,
        DeleteProductImageHandler,

        // Contract bindings
        {
            provide: PRODUCT_VARIANT_REPOSITORY,
            useExisting: PrismaProductVariantRepository,
        },
        {
            provide: PRODUCT_IMAGE_REPOSITORY,
            useExisting: PrismaProductImageRepository,
        },
        {
            provide: STORAGE_SERVICE,
            useExisting: S3StorageService,
        },

        // Repository bindings
        {
            provide: PRODUCT_REPOSITORY,
            useClass: PrismaProductRepository,
        },
    ],
    exports: [PRODUCT_REPOSITORY, PRODUCT_VARIANT_REPOSITORY],
})
export class ProductModule {}
