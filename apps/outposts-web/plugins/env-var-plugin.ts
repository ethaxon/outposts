import dotenv from "dotenv";
import { version } from "../package.json";

const REQUIRED_ENV_NAMES = [
  "AUTH_TYPE",
  "OUTPOSTS_WEB_HOST",
  "CONFLUENCE_API_ENDPOINT",
  "AUTH_ENDPOINT",
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
      AUTH_TYPE: process.env.AUTH_TYPE,
      AUTH_ENDPOINT: process.env.AUTH_ENDPOINT,
      OUTPOSTS_WEB_HOST: process.env.OUTPOSTS_WEB_HOST,
      OUTPOSTS_WEB_AUTH_APPID: process.env.OUTPOSTS_WEB_AUTH_APPID,
      CONFLUENCE_API_ENDPOINT: process.env.CONFLUENCE_API_ENDPOINT,
    });
  },
};

export default envVarPlugin;
