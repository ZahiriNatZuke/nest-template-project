import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ExtractJwt } from 'passport-jwt';
import { Observable } from 'rxjs';
import { JwtService } from '@nestjs/jwt';
import { FastifyRequest } from 'fastify';

@Injectable()
export class VerifyJwtGuard implements CanActivate {
  constructor(private jwtService: JwtService) {
  }

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request: FastifyRequest = context.switchToHttp().getRequest();
    const jwt = ExtractJwt.fromAuthHeaderAsBearerToken()(request);
    try {
      this.jwtService.verify(jwt ?? '');
      return true;
    } catch ( e ) {
      throw new UnauthorizedException(e.message);
    }
  }
}
