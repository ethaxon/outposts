import { Component } from '@angular/core';
import { ButtonModule } from 'primeng/button';
import { RouterModule } from '@angular/router';


@Component({
    standalone: true,
    imports: [ButtonModule, RouterModule],
    template: ` <div class="flex min-h-screen items-center justify-center">
        <div class="flex card flex-col items-center gap-20 sm:p-20">
            <div class="flex flex-col sm:flex-row items-baseline justify-center gap-6 text-primary">
                <span class="font-bold text-9xl"> 4 </span>
                <div class="flex items-center justify-center bg-primary text-primary-contrast rounded-full w-24 h-24">
                    <img src="/image/logo-512.png" alt="logo-512">
                </div>
                <span class="font-bold text-9xl"> 4 </span>
            </div>
            <div class="font-bold text-center text-4xl border-t border-surface pt-20">Page Not Found</div>
            <p-button label="GO TO HOMEPAGE" routerLink="/" />
        </div>
    </div>`
})
export class NotFoundDemoComponent { }
