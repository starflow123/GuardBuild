import { Body, Controller, Post, UnauthorizedException } from "@nestjs/common";
import { AuthService } from "./auth.service";

@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("login")
  login(@Body() dto: { email: string; password: string }) {
    const result = this.authService.login(dto.email, dto.password);
    if (!result) throw new UnauthorizedException("邮箱或密码错误");
    return result;
  }
}
