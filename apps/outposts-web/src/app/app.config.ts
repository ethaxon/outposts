import { ApplicationConfig, provideZoneChangeDetection, DOCUMENT } from '@angular/core';
import { provideRouter, withInMemoryScrolling } from '@angular/router';
import { routes } from './app.routes';
import {
  provideClientHydration,
  withEventReplay,
} from '@angular/platform-browser';
import { AppConfigService } from '@/core/servces/app-config.service';
import { IMAGE_CONFIG } from '@angular/common';
import { AppOverlayService } from '@/core/servces/app-overlay.service';
import Noir from './app-theme';
import { provideHttpClient, withFetch, withInterceptorsFromDi } from '@angular/common/http';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { WINDOW, windowProvider } from '@/core/providers/window';
import { PlatformService } from '@/core/servces/platform.service';
import { providePrimeNG } from 'primeng/config';
import { MessageService } from 'primeng/api';
import { provideMonacoEditor } from 'ngx-monaco-editor-v2';
import { provideTransloco } from '@jsverse/transloco';
import { TranslocoConfig } from '@/app/transloco-config';
import { environment } from '@/environments/environment';

export const appConfig: ApplicationConfig = {
  providers: [
    ...(environment.ssr ? [provideClientHydration(withEventReplay())] : []),
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes, withInMemoryScrolling({ anchorScrolling: 'enabled', scrollPositionRestoration: 'enabled' })),
    provideHttpClient(withInterceptorsFromDi(), withFetch()),
    provideAnimationsAsync(),
    providePrimeNG({
      theme: Noir, ripple: false, // inputStyle: 'outlined',
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
        disableImageLazyLoadWarning: true
      }
    },
  ],
};
