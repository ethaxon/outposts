import { IMAGE_CONFIG } from "@angular/common";
import {
	provideHttpClient,
	withFetch,
	withInterceptorsFromDi,
} from "@angular/common/http";
import {
	type ApplicationConfig,
	DOCUMENT,
	provideZoneChangeDetection,
} from "@angular/core";
import {
	provideClientHydration,
	withEventReplay,
} from "@angular/platform-browser";
import { provideRouter, withInMemoryScrolling } from "@angular/router";
import { provideTransloco } from "@jsverse/transloco";
import { provideMonacoEditor } from "ngx-monaco-editor-v2";
import { MessageService } from "primeng/api";
import { providePrimeNG } from "primeng/config";
import { TranslocoConfig } from "@/app/transloco-config";
import { WINDOW, windowProvider } from "@/core/providers/window";
import { AppConfigService } from "@/core/servces/app-config.service";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import { PlatformService } from "@/core/servces/platform.service";
import { environment } from "@/environments/environment";
import { routes } from "./app.routes";
import Noir from "./app-theme";

export const appConfig: ApplicationConfig = {
	providers: [
		...(environment.ssr ? [provideClientHydration(withEventReplay())] : []),
		provideZoneChangeDetection({ eventCoalescing: true }),
		provideRouter(
			routes,
			withInMemoryScrolling({
				anchorScrolling: "enabled",
				scrollPositionRestoration: "enabled",
			}),
		),
		provideHttpClient(withInterceptorsFromDi(), withFetch()),
		providePrimeNG({
			theme: Noir,
			ripple: false, // inputStyle: 'outlined',
		}),
		{
			provide: WINDOW,
			useFactory: windowProvider,
			deps: [DOCUMENT],
		},
		provideMonacoEditor(),
		provideTransloco(TranslocoConfig),
		PlatformService,
		MessageService,
		AppOverlayService,
		AppConfigService,
		{
			provide: IMAGE_CONFIG,
			useValue: {
				disableImageSizeWarning: true,
				disableImageLazyLoadWarning: true,
			},
		},
	],
};
