import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'identifier', passwordField: 'password' });
  }

  async validate(identifier: string, password: string): Promise<any> {
    const data = await this.authService.validateUser(identifier, password);
    if ( data.status ) return data;
    else throw new UnauthorizedException('Login Failure');
  }
}
