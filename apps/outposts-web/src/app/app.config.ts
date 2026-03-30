import { IMAGE_CONFIG } from "@angular/common";
import { provideHttpClient, withFetch, withInterceptorsFromDi } from "@angular/common/http";
import {
  type ApplicationConfig,
  DOCUMENT,
  importProvidersFrom,
  provideZoneChangeDetection,
} from "@angular/core";
import { provideClientHydration, withEventReplay } from "@angular/platform-browser";
import { provideAnimationsAsync } from "@angular/platform-browser/animations/async";
import { provideRouter, withInMemoryScrolling } from "@angular/router";
import { provideTransloco } from "@jsverse/transloco";
import { AuthModule } from "angular-auth-oidc-client";
import { provideMonacoEditor } from "ngx-monaco-editor-v2";
import { MessageService } from "primeng/api";
import { providePrimeNG } from "primeng/config";
import { TranslocoConfig } from "@/app/transloco-config";
import { WINDOW, windowProvider } from "@/core/providers/window";
import { AppConfigService } from "@/core/servces/app-config.service";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import { PlatformService } from "@/core/servces/platform.service";
import { createOidcAuthConfig } from "@/domain/auth/oidc-auth.config";
import { AUTH_PROVIDERS } from "@/domain/auth/auth.providers";
import { environment } from "@/environments/environment";
import { routes } from "./app.routes";
import Noir from "./app-theme";

export const appConfig: ApplicationConfig = {
  providers: [
    ...(environment.ssr ? [provideClientHydration(withEventReplay())] : []),
    importProvidersFrom(AuthModule.forRoot(createOidcAuthConfig())),
    ...AUTH_PROVIDERS,
    provideAnimationsAsync(),
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
