import { environment } from "@/environments/environment";

export interface ConfluenceAuthConfig {
  /** Base URL of the Confluence API, used as the bearer token URL pattern. */
  resource: string;
}

export const AUTH_CONFLUENCE_CONFIG: ConfluenceAuthConfig = {
  resource: environment.CONFLUENCE_API_ENDPOINT,
};
