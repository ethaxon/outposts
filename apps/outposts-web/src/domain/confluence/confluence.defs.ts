import type { AuthResourceConfig } from "@/domain/auth/auth.defs";
import { environment } from "@/environments/environment";

export const AUTH_CONFLUENCE_CONFIG: AuthResourceConfig = {
  resource: environment.CONFLUENCE_API_ENDPOINT,
  scopes: ["read:confluence", "write:confluence"],
};
