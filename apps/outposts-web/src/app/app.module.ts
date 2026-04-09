import { IMAGE_CONFIG } from "@angular/common";
import { provideHttpClient, withFetch, withInterceptorsFromDi } from "@angular/common/http";
import { DOCUMENT, NgModule, provideZoneChangeDetection } from "@angular/core";
import { FormsModule, ReactiveFormsModule } from "@angular/forms";
import { BrowserModule, provideClientHydration, withEventReplay } from "@angular/platform-browser";
import { provideRouter, RouterOutlet, withInMemoryScrolling } from "@angular/router";
import { MonacoEditorModule } from "ngx-monaco-editor-v2";
import { MessageService } from "primeng/api";
import { providePrimeNG } from "primeng/config";
import { ToastModule } from "primeng/toast";
import { SpinnerComponent } from "@/components/spinner/spinner.component";
import { WINDOW, windowProvider } from "@/core/providers/window";
import { AppConfigService } from "@/core/servces/app-config.service";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import { PlatformService } from "@/core/servces/platform.service";
import { AuthModule as AppAuthModule } from "@/domain/auth/auth.module";
import { provideOidcAuthFromInjectedWindow } from "@/domain/auth/provide-oidc-auth";
import { environment } from "@/environments/environment";
import { AppComponent } from "./app.component";
import { routes } from "./app.routes";
import Noir from "./app-theme";
import { TranslocoRootModule } from "./transloco-root.module";

@NgModule({
  declarations: [AppComponent],
  imports: [
    BrowserModule,
    FormsModule,
    ReactiveFormsModule,
    ToastModule,
    SpinnerComponent,
    TranslocoRootModule,
    MonacoEditorModule.forRoot(),
    RouterOutlet,
    AppAuthModule,
  ],
  providers: [
    ...(environment.ssr ? [provideClientHydration(withEventReplay())] : []),
    {
      provide: WINDOW,
      useFactory: windowProvider,
      deps: [DOCUMENT],
    },
    provideOidcAuthFromInjectedWindow(),
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
      ripple: false, // inputStyle: 'outlined'
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
