import { IsEmail, IsNotEmpty } from 'class-validator';

export class AuthDto {
  name: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsNotEmpty()
  password: string;
}
