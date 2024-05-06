import { Injectable } from '@nestjs/common';
import { User } from '@prisma/client';
import { omit } from 'lodash';

@Injectable()
export class UserMapper {
  private defaultOmit: Array<keyof User> = [
    'password',
    'confirmationToken',
    'resetPasswordToken',
  ];

  public omitDefault(user: User): Partial<User> {
    return this.omit(user, this.defaultOmit);
  }

  public omit(user: User, props: Array<keyof User>): Partial<User> {
    return omit(user, props);
  }
}
