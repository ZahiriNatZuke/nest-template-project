import {
  ArgumentMetadata,
  HttpStatus,
  Injectable,
  NotFoundException,
  ParseUUIDPipe,
  PipeTransform,
} from '@nestjs/common';
import { UserService } from '../user.service';

@Injectable()
export class FindUserByIdPipe implements PipeTransform {
  constructor(private userService: UserService) {
  }

  async transform(value: string, metadata: ArgumentMetadata) {
    return new Promise(async (resolve, reject) => {
      const uuidPipe = new ParseUUIDPipe({
        version: '4',
        errorHttpStatusCode: HttpStatus.BAD_REQUEST,
      });
      await uuidPipe.transform(value, metadata).then(async (id) => {
        try {
          const user = await this.userService.findOne({ id }, true);
          resolve(user);
        } catch ( _ ) {
          reject(new NotFoundException('User not found'));
        }
      }).catch(() => reject(new NotFoundException('UUID not valid')));
    });
  }
}
