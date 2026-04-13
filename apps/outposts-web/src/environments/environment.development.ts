export const environment = {
  APP_HOST: process.env["OUTPOSTS_WEB_HOST"] as string,
  APP_VERSION: process.env["APP_VERSION"] as string,
  CONFLUENCE_API_ENDPOINT: process.env["CONFLUENCE_API_ENDPOINT"] as string,
  production: false,
  ssr: false,
};
