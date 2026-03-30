import dotenv from "dotenv";
import { version } from "../package.json";

const REQUIRED_ENV_NAMES = [
  "OUTPOSTS_WEB_HOST",
  "CONFLUENCE_API_ENDPOINT",
  "CONFLUENCE_OIDC_SCOPES",
  "OIDC_ISSUER",
  "OUTPOSTS_WEB_OIDC_CLIENT_ID",
];

const envVarPlugin = {
  name: "env-var-plugin",
  setup(build: any) {
    const options = build.initialOptions;

    dotenv.config();

    const missingEnvNames = [];
    for (const envName of REQUIRED_ENV_NAMES) {
      if (!process.env[envName]) {
        missingEnvNames.push(envName);
      }
    }

    if (missingEnvNames.length > 0) {
      console.error(`missing required envs: ${missingEnvNames.join(", ")}`);
      process.exit(1);
    }

    options.define["process.env"] = JSON.stringify({
      APP_VERSION: version,
      OIDC_ISSUER: process.env.OIDC_ISSUER,
      OUTPOSTS_WEB_HOST: process.env.OUTPOSTS_WEB_HOST,
      OUTPOSTS_WEB_OIDC_CLIENT_ID: process.env.OUTPOSTS_WEB_OIDC_CLIENT_ID,
      CONFLUENCE_API_ENDPOINT: process.env.CONFLUENCE_API_ENDPOINT,
      CONFLUENCE_OIDC_SCOPES: process.env.CONFLUENCE_OIDC_SCOPES,
    });
  },
};

export default envVarPlugin;
