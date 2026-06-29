import { CommonModule } from "@angular/common";
import { Component, computed, inject, ChangeDetectionStrategy } from "@angular/core";
import { RouterOutlet } from "@angular/router";
import { HlmToaster } from "@/components/ui/sonner";
import { AppConfigService } from "@/core/servces/app-config.service";
import { SpinnerComponent } from "../spinner/spinner.component";
import { AppFooterComponent } from "./footer/app.footer.component";
import { AppMenuComponent } from "./menu/app.menu.component";
import { AppNewsComponent } from "./news/app.news.component";
import { AppTopBarComponent } from "./topbar/app.topbar.component";

@Component({
  selector: "app-main",
  templateUrl: "./app.main.component.html",
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    RouterOutlet,
    AppFooterComponent,
    CommonModule,
    AppNewsComponent,
    AppMenuComponent,
    AppTopBarComponent,
    HlmToaster,
    SpinnerComponent,
  ],
})
export class AppMainComponent {
  configService: AppConfigService = inject(AppConfigService);

  isNewsActive = computed(() => this.configService.newsActive());

  isMenuActive = computed(() => this.configService.appState().menuActive);

  containerClass = computed(() => {
    return {
      "layout-news-active": this.isNewsActive(),
      // 'p-ripple-disabled': this.isRippleDisabled,
    };
  });

  hideMenu() {
    this.configService.hideMenu();
    document.body.classList.remove("blocked-scroll");
  }
}
