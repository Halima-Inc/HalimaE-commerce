import { Inject, Injectable } from '@nestjs/common';
import { ReplaceProductImageCommand } from '../commands';
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
export class ReplaceProductImageHandler {
    constructor(
        @Inject(PRODUCT_IMAGE_REPOSITORY)
        private readonly productImageRepository: IProductImageRepository,
        @Inject(STORAGE_SERVICE)
        private readonly storageService: IStorageService,
    ) {}

    async execute(
        command: ReplaceProductImageCommand,
    ): Promise<ProductImageRecord> {
        const key = this.assertProductImageKey(
            command.productId,
            command.dto.key,
        );
        const url = this.storageService.buildPublicUrl(key);
        const { updated, previousUrl } =
            await this.productImageRepository.replace(
                command.productId,
                command.imageId,
                {
                    url,
                    alt: command.dto.alt,
                    sort: command.dto.sort,
                },
            );

        const previousKey = this.extractKeyFromUrl(previousUrl);
        if (previousKey && previousKey !== key) {
            await this.storageService.deleteObject(previousKey);
        }

        return updated;
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

    private extractKeyFromUrl(url: string): string | null {
        try {
            const parsed = new URL(url);
            const pathname = decodeURIComponent(parsed.pathname);
            return pathname.replace(/^\/+/, '');
        } catch {
            return null;
        }
    }
}
