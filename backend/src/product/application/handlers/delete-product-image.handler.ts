import { Inject, Injectable } from '@nestjs/common';
import { DeleteProductImageCommand } from '../commands';
import {
    PRODUCT_IMAGE_REPOSITORY,
    STORAGE_SERVICE,
} from '../../product.tokens';
import type { IProductImageRepository } from '../../domain/interfaces';
import type { IStorageService } from '../services';

@Injectable()
export class DeleteProductImageHandler {
    constructor(
        @Inject(PRODUCT_IMAGE_REPOSITORY)
        private readonly productImageRepository: IProductImageRepository,
        @Inject(STORAGE_SERVICE)
        private readonly storageService: IStorageService,
    ) {}

    async execute(command: DeleteProductImageCommand): Promise<void> {
        const { deletedUrl } = await this.productImageRepository.delete(
            command.productId,
            command.imageId,
        );

        const key = this.extractKeyFromUrl(deletedUrl);
        if (key) {
            await this.storageService.deleteObject(key);
        }
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
