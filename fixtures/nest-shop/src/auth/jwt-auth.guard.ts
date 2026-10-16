import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";

/** 校验请求已注入当前用户（真实项目在此解析 Bearer JWT）。 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();
    if (!req.user) throw new UnauthorizedException("未登录");
    return true;
  }
}
