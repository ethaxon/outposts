import dotenv from 'dotenv';
import { version } from '../package.json';

const envVarPlugin = {
    name: 'env-var-plugin',
    setup(build) {
        const options = build.initialOptions;

        dotenv.config();

        if (
            !process.env.AUTH_TYPE ||
            !process.env.OUTPOSTS_WEB_HOST ||
            !process.env.CONFLUENCE_API_ENDPOINT ||
            !process.env.AUTH_ENDPOINT
        ) {
            console.error('missing required envs');
            process.exit(1);
        }

        options.define['process.env'] = JSON.stringify({
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
