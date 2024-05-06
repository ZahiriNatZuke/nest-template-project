import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { mkdirSync, rmSync } from 'fs';
import { join } from 'path';

@Injectable()
export class TasksService {
  readonly #logger = new Logger(TasksService.name);

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  handleCron() {
    rmSync(join(process.cwd(), 'temp'), { recursive: true, force: true });
    mkdirSync('temp');
    this.#logger.debug('>> Deleted all the directories of the [temp] folder');
  }

}
