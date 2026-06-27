import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { ProductImageUploadUrlResponseDto } from '../../presentation/dto';
import { CreateProductImageUploadUrlCommand } from '../commands';
import { PRODUCT_REPOSITORY, STORAGE_SERVICE } from '../../product.tokens';
import type { IProductRepository } from '../../domain/interfaces';
import type { IStorageService } from '../services';
import {
    ProductNotFoundException,
    ProductValidationException,
} from '../../domain/exceptions';

type AllowedImageExtension = 'jpg' | 'png' | 'webp';

const CONTENT_TYPE_TO_EXTENSION: Record<string, AllowedImageExtension> = {
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp',
};

@Injectable()
export class CreateProductImageUploadUrlHandler {
    constructor(
        @Inject(PRODUCT_REPOSITORY)
        private readonly productRepository: IProductRepository,
        @Inject(STORAGE_SERVICE)
        private readonly storageService: IStorageService,
    ) {}

    async execute(
        command: CreateProductImageUploadUrlCommand,
    ): Promise<ProductImageUploadUrlResponseDto> {
        const exists = await this.productRepository.existsById(
            command.productId,
        );
        if (!exists) {
            throw new ProductNotFoundException(
                `Product with ID ${command.productId} not found.`,
            );
        }

        const extension = CONTENT_TYPE_TO_EXTENSION[command.contentType];
        if (!extension) {
            throw new ProductValidationException(
                'Unsupported content type. Allowed: image/jpeg, image/png, image/webp.',
            );
        }

        const key = `products/${command.productId}/${Date.now()}-${randomUUID()}.${extension}`;
        const signed = await this.storageService.createSignedUploadUrl({
            key,
            contentType: command.contentType,
        });

        return {
            key,
            uploadUrl: signed.uploadUrl,
            method: 'PUT',
            expiresIn: signed.expiresIn,
        };
    }
}
