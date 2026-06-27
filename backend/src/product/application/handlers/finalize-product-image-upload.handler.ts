import { Inject, Injectable } from '@nestjs/common';
import { FinalizeProductImageUploadCommand } from '../commands';
import {
    PRODUCT_IMAGE_REPOSITORY,
    STORAGE_SERVICE,
} from '../../product.tokens';
import type {
    IProductImageRepository,
    ProductImageRecord,
} from '../../domain/interfaces';
import type { IStorageService } from '../services';
import { ProductValidationException } from '../../domain/exceptions';

@Injectable()
export class FinalizeProductImageUploadHandler {
    constructor(
        @Inject(PRODUCT_IMAGE_REPOSITORY)
        private readonly productImageRepository: IProductImageRepository,
        @Inject(STORAGE_SERVICE)
        private readonly storageService: IStorageService,
    ) {}

    async execute(
        command: FinalizeProductImageUploadCommand,
    ): Promise<ProductImageRecord> {
        const key = this.assertProductImageKey(
            command.productId,
            command.dto.key,
        );
        const url = this.storageService.buildPublicUrl(key);

        return this.productImageRepository.create(command.productId, {
            url,
            alt: command.dto.alt,
            sort: command.dto.sort,
        });
    }

    private assertProductImageKey(productId: string, key: string): string {
        const normalized = key.replace(/^\/+/, '');
        const prefix = `products/${productId}/`;

        if (!normalized.startsWith(prefix)) {
            throw new ProductValidationException(
                'Image key does not belong to this product upload namespace.',
            );
        }

        return normalized;
    }
}
