export const environment = {
  APP_VERSION: process.env["APP_VERSION"] as string,
  CONFLUENCE_API_ENDPOINT: process.env["CONFLUENCE_API_ENDPOINT"] as string,
  AUTH_TYPE: process.env["AUTH_TYPE"] as string,
  production: true,
} as const;
