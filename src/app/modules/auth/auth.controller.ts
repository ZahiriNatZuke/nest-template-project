import { Body, Get, Headers, HttpStatus, Post, Req, Res, UnauthorizedException, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Session, User } from '@prisma/client';
import { UserService } from '../user/user.service';
import { AuthRole } from './enums/auth-role';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { UserMapper } from '../user/user.mapper';
import { Auth } from './decorators/auth.decorator';
import { SetController } from '../../core/decorators/set-controller.decorator';
import { FastifyReply, FastifyRequest } from 'fastify';
import { LoginZodDto } from './dto/login.dto';
import { RefreshZodDto } from './dto/refresh.dto';
import { UpdatePasswordZodDto } from './dto/update-password.dto';
import { RequestRecoveryAccountZodDto } from './dto/request-recovery-account.dto';
import { RecoveryAccountZodDto } from './dto/recovery-account.dto';
import { TokenZodDto } from './dto/token.dto';

@SetController('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private userService: UserService,
    private userMapper: UserMapper,
  ) {
  }

  @Post('login')
  @UseGuards(LocalAuthGuard)
  async login(
    @Res() res: FastifyReply,
    @Body() loginDTO: LoginZodDto,
    @Req() { user }: FastifyRequest & { user: User },
  ) {
    const { device } = loginDTO;

    const valid: {
      user: Partial<User> | null;
      statusCode: boolean | 'miss_activate';
    } = <any>user;
    if ( !valid.user ) throw new UnauthorizedException('Login Failure');
    const session: Session = await this.authService.generateSession(
      valid.user,
      device,
    );

    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      data: {
        access: session.accessToken,
        refresh: session.refreshToken,
        user: valid.user,
      },
      message: 'Login Success',
    });
  }

  @Get('me')
  @Auth(Object.values(AuthRole))
  async me(@Res() res: FastifyReply, @Req() req: FastifyRequest & { user: User }) {
    const { id } = <User>req.user;
    const user = await this.userService.findOne({ id });
    if ( !user )
      return res.code(HttpStatus.NOT_FOUND);
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      data: this.userMapper.omitDefault(user),
    });
  }

  @Post('refresh')
  async refresh(@Res() res: FastifyReply, @Body() refreshDto: RefreshZodDto) {
    const data = await this.authService.refreshSession(refreshDto.refresh);
    if ( data ) {
      return res.code(HttpStatus.OK).send({
        statusCode: 200,
        data: {
          access: data.session.accessToken,
          refresh: data.session.refreshToken,
          user: this.userMapper.omitDefault(data.user),
        },
        message: 'Refresh session successfully',
      });
    }

    return res.code(HttpStatus.UNAUTHORIZED).send({
      statusCode: 401,
      message: 'Refresh Failure',
    });
  }

  @Get('logout')
  @Auth(Object.values(AuthRole))
  async logout(
    @Res() res: FastifyReply,
    @Headers('Authorization') headers: string,
  ) {
    const accessToken = headers.split(' ')[ 1 ];
    const result = await this.authService.closeSession(accessToken);
    if ( result )
      return res.code(HttpStatus.OK).send({
        statusCode: 200,
        message: 'Logout Success',
      });
    else
      return res.code(HttpStatus.FORBIDDEN).send({
        statusCode: 403,
        message: 'Logout Failure',
      });
  }

  @Post('update-password')
  @Auth(Object.values(AuthRole))
  async updatePassword(
    @Res() res: FastifyReply,
    @Body() updatePasswordDto: UpdatePasswordZodDto,
    @Req() req: FastifyRequest & { user: User },
  ) {
    await this.authService.updatePassword(updatePasswordDto, <User>req.user);

    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      message: 'Password changed successfully',
    });
  }

  @Post('request-recovery-account')
  async requestRecoveryAccount(
    @Res() res: FastifyReply,
    @Body() requestRecoveryAccountDto: RequestRecoveryAccountZodDto,
  ) {
    await this.authService.requestRecoveryAccount(requestRecoveryAccountDto);
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      message: 'Recovery account process started, now check the sms that you will receive in your phone',
    });
  }

  @Post('recovery-account')
  async recoveryAccount(
    @Res() res: FastifyReply,
    @Body() recoveryAccountDto: RecoveryAccountZodDto,
  ) {
    await this.authService.recoverAccount(recoveryAccountDto);
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      message: 'Recovery account successfully, now you can go to login page',
    });
  }

  @Post('verify-token')
  async verifyToken(@Res() res: FastifyReply, @Body() { token }: TokenZodDto) {
    const status = await this.authService.decodeVerificationToken(token);
    if ( status )
      return res.code(HttpStatus.OK).send({
        statusCode: 200,
        message: 'Verification process successfully',
      });
    else
      return res.code(HttpStatus.BAD_REQUEST).send({
        statusCode: 400,
        message: 'Verification process failure',
      });
  }
}
