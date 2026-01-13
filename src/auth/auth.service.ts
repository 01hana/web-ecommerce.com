import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as argon from 'argon2';
import { AuthDto } from './dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signin(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Credentials incorrect');
    }

    const pwMattches = await argon.verify(user.hash, dto.password);

    if (!pwMattches) {
      throw new ForbiddenException('Credentials incorrect');
    }

    // 使用解構賦值排除 hash，剩餘欄位存入 result
    const { hash: _, ...result } = user;

    return result;
  }

  async signup(dto: AuthDto) {
    try {
      const hash = await argon.hash(dto.password);

      const user = await this.prisma.user.create({
        data: {
          name: dto.name,
          email: dto.email,
          hash,
        },
      });

      // 使用解構賦值排除 hash，剩餘欄位存入 result
      const { hash: _, ...result } = user;

      return result;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }

      throw error;
    }
  }
}
