import { TranslocoHttpLoader } from "@/app/transloco-loader";
import { environment } from "@/environments/environment";

export const TranslocoConfig = {
	config: {
		availableLangs: ["en", "zh_CN", "zh_TW"],
		defaultLang: "en",
		// Remove this option if your application doesn't support changing language in runtime.
		reRenderOnLangChange: true,
		prodMode: environment.production,
	},
	loader: TranslocoHttpLoader,
};
