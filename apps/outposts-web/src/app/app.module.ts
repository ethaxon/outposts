import { IMAGE_CONFIG } from "@angular/common";
import { provideHttpClient, withFetch, withInterceptorsFromDi } from "@angular/common/http";
import { DOCUMENT, NgModule, provideZoneChangeDetection } from "@angular/core";
import { FormsModule, ReactiveFormsModule } from "@angular/forms";
import { BrowserModule, provideClientHydration, withEventReplay } from "@angular/platform-browser";
import { provideRouter, RouterOutlet, withInMemoryScrolling } from "@angular/router";
import { MonacoEditorModule } from "ngx-monaco-editor-v2";
import type * as Monaco from "monaco-editor";
import { MessageService } from "primeng/api";
import { providePrimeNG } from "primeng/config";
import { ToastModule } from "primeng/toast";
import { SpinnerComponent } from "@/components/spinner/spinner.component";
import { WINDOW, windowProvider } from "@/core/providers/window";
import { AppConfigService } from "@/core/servces/app-config.service";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import { PlatformService } from "@/core/servces/platform.service";
import { provideAuth } from "@/domain/auth/auth.providers";
import { CLASH_META_CONFIG_TYPES } from "@/domain/confluence/types/clash-meta-config.extra-lib";
import { environment } from "@/environments/environment";
import { AppComponent } from "./app.component";
import { routes } from "./app.routes";
import Noir from "./app-theme";
import { TranslocoRootModule } from "./transloco-root.module";

const PROFILE_SCRIPT_TYPES = `${CLASH_META_CONFIG_TYPES.replace(/^export /gm, "")}

type CommonProfileRequestHeader =
  | "accept"
  | "accept-encoding"
  | "accept-language"
  | "authorization"
  | "cache-control"
  | "cf-connecting-ip"
  | "connection"
  | "cookie"
  | "dnt"
  | "forwarded"
  | "host"
  | "origin"
  | "pragma"
  | "referer"
  | "sec-ch-ua"
  | "sec-ch-ua-mobile"
  | "sec-ch-ua-platform"
  | "sec-fetch-dest"
  | "sec-fetch-mode"
  | "sec-fetch-site"
  | "true-client-ip"
  | "user-agent"
  | "x-forwarded-for"
  | "x-forwarded-host"
  | "x-forwarded-proto"
  | "x-real-ip";

type ProfileTransformHeaders = Record<string, string | undefined> &
  Partial<Record<CommonProfileRequestHeader, string>>;

interface ProfileTransformRequest {
  headers: ProfileTransformHeaders;
  url: string;
  body: string;
}

interface ProfileTransformContext {
  request: ProfileTransformRequest;
  profile: ClashMetaConfig;
}
`;

function configureMonacoTypes() {
  const monaco = (globalThis as typeof globalThis & { monaco?: typeof Monaco }).monaco;
  monaco?.typescript.typescriptDefaults.addExtraLib(
    PROFILE_SCRIPT_TYPES,
    "outposts://confluence/profile-transform.d.ts",
  );
}

@NgModule({
  declarations: [AppComponent],
  imports: [
    BrowserModule,
    FormsModule,
    ReactiveFormsModule,
    ToastModule,
    SpinnerComponent,
    TranslocoRootModule,
    MonacoEditorModule.forRoot({
      onMonacoLoad: configureMonacoTypes,
    }),
    RouterOutlet,
  ],
  providers: [
    ...(environment.ssr ? [provideClientHydration(withEventReplay())] : []),
    {
      provide: WINDOW,
      useFactory: windowProvider,
      deps: [DOCUMENT],
    },
    ...provideAuth(typeof document !== "undefined" ? document.defaultView! : ({} as Window)),
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
      ripple: false,
    }),
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
  bootstrap: [AppComponent],
})
export class AppModule {}
