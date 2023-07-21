import {
  BadRequestException,
  Body,
  Controller,
  NotFoundException,
  Post,
} from '@nestjs/common';
import { ResetService } from './reset.service';
import { MailerService } from '@nestjs-modules/mailer';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';

@Controller()
export class ResetController {
  constructor(
    private resetService: ResetService,
    private mailService: MailerService,
    private userService: UserService,
  ) {}

  @Post('forgot')
  async forgot(@Body('email') email: string) {
    const token = Math.random().toString(20).substring(2, 12);

    await this.resetService.save({
      email,
      token,
    });

    const url = `http://localhost:3000/reset/${token}`;

    await this.mailService.sendMail({
      to: email,
      subject: 'Reset your password',
      html: 'Click <a href="${url}>here</a> to reset your password!',
    });

    return {
      message: 'Check your email',
    };
  }

  @Post('reset')
  async reset(
    @Body('token') token: string,
    @Body('password') password: string,
    @Body('password_confirm') password_confirm: string,
  ) {
    if (password !== password_confirm) {
      throw new BadRequestException('Passwords do not match!');
    }

    const reset = await this.resetService.findOne({ token });

    const user = await this.userService.findOne({ email: reset.email });

    if (!user) {
      throw new NotFoundException('User not found!');
    }

    await this.userService.update(user.id, {
      password: await bcrypt.hash(password, 12),
    });

    return {
      message: 'success',
    };
  }
}
