import { NgModule, provideZoneChangeDetection, DOCUMENT } from '@angular/core';
import { BrowserModule, provideClientHydration, withEventReplay } from '@angular/platform-browser';
import { AppComponent } from './app.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import {
    provideHttpClient,
    withFetch,
    withInterceptorsFromDi,
} from '@angular/common/http';
import { TranslocoRootModule } from './transloco-root.module';
import { WINDOW, windowProvider } from '@/core/providers/window';
import { IMAGE_CONFIG } from '@angular/common';
import { MonacoEditorModule } from 'ngx-monaco-editor-v2';
import { AuthModule } from '@/domain/auth/auth.module';
import { MessageService } from 'primeng/api';
import { AppOverlayService } from '@/core/servces/app-overlay.service';
import { ToastModule } from 'primeng/toast';
import { SpinnerComponent } from '@/components/spinner/spinner.component';
import { environment } from '@/environments/environment';
import { provideRouter, RouterOutlet, withInMemoryScrolling } from '@angular/router';
import { routes } from './app.routes';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import Noir from './app-theme';
import { providePrimeNG } from 'primeng/config';
import { PlatformService } from '@/core/servces/platform.service';
import { AppConfigService } from '@/core/servces/app-config.service';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';

@NgModule({
    declarations: [AppComponent],
    imports: [
        BrowserModule,
        BrowserAnimationsModule,
        FormsModule,
        ReactiveFormsModule,
        AuthModule,
        ToastModule,
        SpinnerComponent,
        TranslocoRootModule,
        MonacoEditorModule.forRoot(),
        RouterOutlet
    ],
    providers: [
        ...(environment.ssr ? [provideClientHydration(withEventReplay())] : []),
        provideZoneChangeDetection({ eventCoalescing: true }),
        provideRouter(routes, withInMemoryScrolling({ anchorScrolling: 'enabled', scrollPositionRestoration: 'enabled' })),
        provideHttpClient(withInterceptorsFromDi(), withFetch()),
        provideAnimationsAsync(),
        providePrimeNG({
            theme: Noir, ripple: false, // inputStyle: 'outlined'
        }),
        {
            provide: WINDOW,
            useFactory: windowProvider,
            deps: [DOCUMENT],
        },
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
    bootstrap: [AppComponent],
})
export class AppModule {

}