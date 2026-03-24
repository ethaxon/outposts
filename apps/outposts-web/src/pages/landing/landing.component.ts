import { CommonModule } from "@angular/common";
import { Component, computed, inject, type OnInit } from "@angular/core";
import { Meta, Title } from "@angular/platform-browser";
import { ButtonModule } from "primeng/button";
import { ToastModule } from "primeng/toast";
import type { Subscription } from "rxjs";
import { AppNewsComponent } from "@/components/layout/news/app.news.component";
import { AppTopBarComponent } from "@/components/layout/topbar/app.topbar.component";
import { AppConfigService } from "@/core/servces/app-config.service";
import { FooterSectionComponent } from "./footersection.component";
import { HeroSectionComponent } from "./herosection.component";

@Component({
	selector: "app-landing",
	standalone: true,
	templateUrl: "./landing.component.html",
	imports: [
		CommonModule,
		AppNewsComponent,
		AppTopBarComponent,
		ButtonModule,
		HeroSectionComponent,
		FooterSectionComponent,
		ToastModule,
	],
})
export class LandingComponent implements OnInit {
	subscription!: Subscription;

	isNewsActive = computed(() => this.configService.newsActive());

	isDarkMode = computed(() => this.configService.appState().darkTheme);

	landingClass = computed(() => {
		return {
			"layout-dark": this.isDarkMode(),
			"layout-light": !this.isDarkMode(),
			"layout-news-active": this.isNewsActive(),
		};
	});

  private configService = inject(AppConfigService);
  private metaService = inject(Meta);
  private titleService = inject(Title);

	ngOnInit() {
		this.titleService.setTitle(
			"OUTPOSTS - My personal digital outpost for side projects and homelabs",
		);
		this.metaService.updateTag({
			name: "description",
			content:
				"OUTPOSTS: Build my personal digital outpost—streamline your side projects and homelab with essential tools and features, inspired by the spirit of exploration.",
		});
	}
}
