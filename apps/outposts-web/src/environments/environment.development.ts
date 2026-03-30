export const environment = {
  APP_HOST: process.env["OUTPOSTS_WEB_HOST"] as string,
  OIDC_CLIENT_ID: process.env["OUTPOSTS_WEB_OIDC_CLIENT_ID"] as string,
  OIDC_ISSUER: process.env["OIDC_ISSUER"] as string,
  APP_VERSION: process.env["APP_VERSION"] as string,
  CONFLUENCE_API_ENDPOINT: process.env["CONFLUENCE_API_ENDPOINT"] as string,
  CONFLUENCE_OIDC_SCOPES: process.env["CONFLUENCE_OIDC_SCOPES"] as string,
  production: false,
  ssr: false,
};
