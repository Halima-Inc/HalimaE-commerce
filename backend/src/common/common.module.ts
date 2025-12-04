import { Global, Module } from '@nestjs/common';
import { CacheService } from './cache.service';


/**
 * TODO: Add common providers, controllers, exports here
 *  LOGSERVICE, PRISMA, EMAIL SERVICE.
 */

@Global()
@Module({
    providers: [CacheService],
    exports: [CacheService],
})
export class CommonModule {}
