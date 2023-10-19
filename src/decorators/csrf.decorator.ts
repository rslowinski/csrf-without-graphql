import { applyDecorators, UseGuards } from "@nestjs/common";

import { CsrfGuard } from "../guards/csrf.guard";

export const Csrf = (message?: string) => {
  return applyDecorators(UseGuards(new CsrfGuard(message)));
};

