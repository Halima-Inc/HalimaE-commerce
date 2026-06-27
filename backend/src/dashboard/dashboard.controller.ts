import { Controller, Get, UseGuards } from '@nestjs/common';
import {
    ApiTags,
    ApiOperation,
    ApiBearerAuth,
    ApiExtraModels,
} from '@nestjs/swagger';
import {
    ApiStandardResponse,
    ApiStandardErrorResponse,
} from '../common/swagger/api-response.decorator';
import { CacheService } from '../common/cache.service';
import {
    DashboardDto,
    SalesByPeriodDto,
    PeakPeriodDto,
    OrdersByLocationDto,
    BestSellingProductDto,
    LowStockProductDto,
} from './dto';
import { DashboardService } from './dashboard.service';
import {
    JwtAccessTokenGuard,
    RequiredRoles,
    RolesGuard,
} from '../auth/presentation';

@ApiTags('dashboard')
@ApiBearerAuth('JWT-auth')
@ApiExtraModels(
    DashboardDto,
    SalesByPeriodDto,
    PeakPeriodDto,
    OrdersByLocationDto,
    BestSellingProductDto,
    LowStockProductDto,
)
@UseGuards(JwtAccessTokenGuard, RolesGuard)
@RequiredRoles('admin', 'employee')
@Controller('dashboard')
export class DashboardController {
    constructor(
        private readonly cacheService: CacheService,
        private readonly dashboardService: DashboardService,
    ) {}

    @Get()
    @ApiOperation({
        summary: 'Get dashboard metrics',
        description:
            'Returns cached dashboard metrics including revenue, orders, customers, products, and inventory statistics. Metrics are read from dashboard projections and cached for performance.',
    })
    @ApiStandardResponse(
        DashboardDto,
        'Dashboard metrics retrieved successfully',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        403,
        'Forbidden',
        'Admin or employee role required',
    )
    async getDashboardMetrics(): Promise<DashboardDto> {
        // Try to get from cache first
        const cached =
            await this.cacheService.get<DashboardDto>('dashboard-metrics');

        if (cached) {
            return cached;
        }

        // If no cache, compute on-demand (first request or cache expired)
        const metrics = await this.dashboardService.computeDashboardMetrics();
        await this.cacheService.set('dashboard-metrics', metrics, 60 * 10); // Cache for 10 minutes

        return metrics;
    }

    @Get('refresh')
    @ApiOperation({
        summary: 'Force refresh dashboard metrics',
        description:
            'Bypasses the cache and reloads dashboard metrics from projections immediately. Use this when you need the most up-to-date projection state. The refreshed metrics are cached for subsequent requests.',
    })
    @ApiStandardResponse(
        DashboardDto,
        'Dashboard metrics refreshed successfully',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(
        403,
        'Forbidden',
        'Admin or employee role required',
    )
    async refreshDashboardMetrics(): Promise<DashboardDto> {
        const metrics = await this.dashboardService.computeDashboardMetrics();
        await this.cacheService.set('dashboard-metrics', metrics, 60 * 10);
        return metrics;
    }
}
