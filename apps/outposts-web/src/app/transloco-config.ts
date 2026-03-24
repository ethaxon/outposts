import { TranslocoHttpLoader } from "@/app/transloco-loader";
import { environment } from "@/environments/environment";

export const AVAILABLE_LANGS = ["en", "zh_CN"] as const;
export type AppLang = (typeof AVAILABLE_LANGS)[number];
export const DEFAULT_LANG: AppLang = "en";

export const TranslocoConfig = {
  config: {
    availableLangs: [...AVAILABLE_LANGS],
    defaultLang: DEFAULT_LANG,
    fallbackLang: DEFAULT_LANG,
    reRenderOnLangChange: true,
    prodMode: environment.production,
  },
  loader: TranslocoHttpLoader,
};
