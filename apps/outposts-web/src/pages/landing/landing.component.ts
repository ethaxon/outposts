import { CommonModule } from "@angular/common";
import { Component, computed, DestroyRef, inject, type OnInit } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { TranslocoService } from "@jsverse/transloco";
import { Meta, Title } from "@angular/platform-browser";
import { ButtonModule } from "primeng/button";
import { ToastModule } from "primeng/toast";
import { combineLatest } from "rxjs";
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
  private destroyRef = inject(DestroyRef);
  private translocoService = inject(TranslocoService);

  ngOnInit() {
    combineLatest([
      this.translocoService.selectTranslate("landing.meta.title"),
      this.translocoService.selectTranslate("landing.meta.description"),
    ])
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(([title, description]) => {
        this.titleService.setTitle(title);
        this.metaService.updateTag({
          name: "description",
          content: description,
        });
      });
  }
}
