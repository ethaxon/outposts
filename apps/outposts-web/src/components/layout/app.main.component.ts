import { CommonModule } from "@angular/common";
import { Component, computed, inject } from "@angular/core";
import { RouterOutlet } from "@angular/router";
import { PrimeNG } from "primeng/config";
import { DomHandler } from "primeng/dom";
import { ToastModule } from "primeng/toast";
import { AppConfigService } from "@/core/servces/app-config.service";
import { SpinnerComponent } from "../spinner/spinner.component";
import { AppFooterComponent } from "./footer/app.footer.component";
import { AppMenuComponent } from "./menu/app.menu.component";
import { AppNewsComponent } from "./news/app.news.component";
import { AppTopBarComponent } from "./topbar/app.topbar.component";

@Component({
	selector: "app-main",
	template: `
        <div class="layout-wrapper" [ngClass]="containerClass()">
            <app-news />
            <app-topbar />
            <div class="layout-mask" [ngClass]="{ 'layout-mask-active': isMenuActive() }" (click)="hideMenu()" tabindex="0" (keyup)="hideMenu()"></div>
            <div class="layout-content">
                <app-menu />
                <div class="layout-content-slot">
                    <p-toast [baseZIndex]="9999" />
                    <router-outlet></router-outlet>
                </div>
            </div>
            <app-footer />
        </div>
        <app-spinner />
    `,
	standalone: true,
	imports: [
		RouterOutlet,
		AppFooterComponent,
		CommonModule,
		AppNewsComponent,
		AppMenuComponent,
		AppTopBarComponent,
		ToastModule,
		SpinnerComponent,
	],
})
export class AppMainComponent {
	configService: AppConfigService = inject(AppConfigService);

	primeng: PrimeNG = inject(PrimeNG);

	isNewsActive = computed(() => this.configService.newsActive());

	isMenuActive = computed(() => this.configService.appState().menuActive);

	isRippleDisabled = computed(() => this.primeng.ripple());

	containerClass = computed(() => {
		return {
			"layout-news-active": this.isNewsActive(),
			// 'p-ripple-disabled': this.isRippleDisabled,
		};
	});

	hideMenu() {
		this.configService.hideMenu();
		DomHandler.unblockBodyScroll("blocked-scroll");
	}
}
