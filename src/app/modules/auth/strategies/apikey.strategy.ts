import { HeaderAPIKeyStrategy } from 'passport-headerapikey';
import { PassportStrategy } from '@nestjs/passport';
import { HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { envs } from '../../../../config/envs';

declare type doneFn = (error: UnauthorizedException | null, data: boolean | null) => unknown;

@Injectable()
export class ApiKeyStrategy extends PassportStrategy(HeaderAPIKeyStrategy, 'ApiKey') {
  constructor(private authService: AuthService) {
    super(
      { header: envs.HEADER_KEY_API_KEY, prefix: '' },
      true,
      async (apiKey: string, done: doneFn) => this.validate(apiKey, done),
    );
  }

  async validate(apiKey: string, done: doneFn) {
    ( await this.authService.validateApiKey(apiKey) )
      ? done(null, true)
      : done(
        new UnauthorizedException({
          statusCode: HttpStatus.UNAUTHORIZED,
          message: 'Api Key Failure',
        }),
        null,
      );
  }
}
