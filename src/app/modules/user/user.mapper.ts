import { SafeUser } from '@app/core/types';
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

	public omitDefault(user: User): SafeUser {
		return this.omit(user, this.defaultOmit) as SafeUser;
	}

	public omit(user: User, props: Array<keyof User>): Partial<User> {
		return omit(user, props);
	}
}
