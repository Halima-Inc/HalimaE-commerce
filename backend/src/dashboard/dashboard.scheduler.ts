import { Injectable } from "@nestjs/common";
import { LogService } from "../logger/log.service";
import { type Queue } from "bull";
import { InjectQueue } from "@nestjs/bull";
import { Cron } from "@nestjs/schedule";

@Injectable()
export class DashboardScheduler {
    constructor(
        private readonly logger: LogService,

        @InjectQueue('dashboard-queue')
        private readonly queue : Queue,
    ) {}

    @Cron('*/5 * * * *') // Every 5 minutes
    async enqueueEvery5Min() {
        this.queue.add('compute-dashboard', { }, {
            removeOnComplete: true,
            removeOnFail    : false
        });

        this.logger.debug('Enqueued compute-dashboard job every 5 minutes', DashboardScheduler.name);
    }

    @Cron('0 2 * * *') // Every day at 2 AM
    async enqueueNightly() {
        this.queue.add('compute-dashboard', { full: true }, {
            removeOnComplete: true
        });

        this.logger.debug('Enqueued compute-dashboard job nightly', DashboardScheduler.name);
    }
}
