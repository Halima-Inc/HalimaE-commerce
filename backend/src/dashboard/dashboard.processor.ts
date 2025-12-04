import { Process, Processor } from "@nestjs/bull";
import { DashboardService } from "./dashboard.service";
import { CacheService } from "../common/cache.service";
import { type Job } from "bull";
import { LogService } from "../logger/log.service";

@Processor('dashboard-queue')
export class DashboardProcessor {
    constructor(
        private readonly dashboardService: DashboardService,
        private readonly cacheService: CacheService,
        private readonly logger: LogService,
    ) {}

    @Process('compute-dashboard')
    async handleCompute(job: Job) {
        try {
            const metrics = await this.dashboardService.computeDashboardMetrics();

            // Store in Redis with TTL, if worker fails, stale remains temporarily.
            await this.cacheService.set('dashboard-metrics', metrics, 60 * 10); // Cache for 10 minutes

            this.logger.log(`Dashboard metrics computed and cached successfully.`, DashboardProcessor.name);

            return { ok: true };
        } catch (error: Error | any) {
            this.logger.error(`Error computing dashboard metrics: ${error.message}`, DashboardProcessor.name);
            throw error;
        }
    }
}
