import type { AuthResourceConfig } from "@/domain/auth/auth.defs";
import { environment } from "@/environments/environment";

function parseScopes(raw: string): string[] {
  return raw
    .split(/[,\s]+/u)
    .map((scope) => scope.trim())
    .filter((scope, index, scopes) => scope.length > 0 && scopes.indexOf(scope) === index);
}

export const AUTH_CONFLUENCE_CONFIG: AuthResourceConfig = {
  resource: environment.CONFLUENCE_API_ENDPOINT,
  scopes: parseScopes(environment.CONFLUENCE_OIDC_SCOPES),
};
