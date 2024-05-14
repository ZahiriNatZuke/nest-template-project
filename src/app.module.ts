import { Module } from '@nestjs/common';
import { PrismaModule } from './app/core/modules/prisma/prisma.module';
import { TasksService } from './app/core/services/tasks.service';
import { ScheduleModule } from '@nestjs/schedule';
import { AuthModule } from './app/modules/auth/auth.module';
import { UserModule } from './app/modules/user/user.module';
import { SettingsModule } from './app/modules/settings/settings.module';
import { RoleModule } from './app/modules/role/role.module';
import { SessionModule } from './app/modules/session/session.module';
import { ApiKeyModule } from './app/modules/api-key/api-key.module';
import { LoggerModule } from 'nestjs-pino';
import { createStream } from 'rotating-file-stream';
import { envs } from './config/envs';

@Module({
  imports: [
    ScheduleModule.forRoot(),
    PrismaModule,
    LoggerModule.forRoot({
      pinoHttp: [
        {
          level: envs.PINO_LOG_LEVEL || 'info',
          formatters: {
            level: (label) => {
              return { level: label.toUpperCase() };
            },
            bindings: (bindings) => {
              return {
                pid: bindings.pid,
                host: bindings.hostname,
                node_version: process.version,
              };
            },
          },
          transport: {
            target: 'pino-pretty',
            options: {
              colorize: true,
              colorizeObjects: true,
              singleLine: true,
              translateTime: 'HH:MM:ss',
            },
          },
          customLevels: {
            emerg: 80,
            alert: 70,
            crit: 60,
            error: 50,
            warn: 40,
            notice: 30,
            info: 20,
            debug: 10,
          },
          useOnlyCustomLevels: true,
        },
        createStream(
          (time: Date, index: number) => {
            if ( !time ) {
              return `nest-template-project-current.log`;
            }

            let filename = time.toISOString().slice(0, 10);
            if ( index > 1 ) {
              filename += `.${ index }`;
            }

            return `nest-project-${ filename }.log.gz`;
          },
          {
            path: './logs',
            initialRotation: true,
            interval: '1d',
            maxSize: '100M',
            maxFiles: 10,
            compress: 'gzip',
          },
        ),
      ],
    }),
    AuthModule,
    UserModule,
    SettingsModule,
    RoleModule,
    SessionModule,
    ApiKeyModule,
  ],
  providers: [ TasksService ],
})
export class AppModule {
}
