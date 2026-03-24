import { CommonModule } from "@angular/common";
import {
  afterNextRender,
  booleanAttribute,
  Component,
  computed,
  ElementRef,
  Input,
  inject,
  type OnDestroy,
  Renderer2,
} from "@angular/core";
import { FormsModule } from "@angular/forms";
import { TranslocoModule } from "@jsverse/transloco";
import { RouterModule } from "@angular/router";
import { DomHandler } from "primeng/dom";
import { StyleClass } from "primeng/styleclass";
import Versions from "@/assets/data/versions.json";
import type { AppLang } from "@/app/transloco-config";
import { WINDOW } from "@/core/providers/window";
import { AppConfigService } from "@/core/servces/app-config.service";
import { AppI18nService } from "@/core/servces/app-i18n.service";

@Component({
  selector: "app-topbar",
  standalone: true,
  imports: [CommonModule, FormsModule, StyleClass, RouterModule, TranslocoModule],
  templateUrl: "./app.topbar.component.html",
})
export class AppTopBarComponent implements OnDestroy {
  @Input({ transform: booleanAttribute }) showConfigurator = true;

  @Input({ transform: booleanAttribute }) showMenuButton = true;

  versions: typeof Versions = Versions;

  scrollListener?: VoidFunction;

  private window: Window = inject(WINDOW);
  private renderer: Renderer2 = inject(Renderer2);
  private el: ElementRef = inject(ElementRef);
  private configService: AppConfigService = inject(AppConfigService);
  private i18nService: AppI18nService = inject(AppI18nService);

  constructor() {
    afterNextRender(() => {
      this.bindScrollListener();
    });
  }

  isDarkMode = computed(() => this.configService.appState().darkTheme);

  isMenuActive = computed(() => this.configService.appState().menuActive);

  activeLang = computed(() => this.i18nService.activeLang());

  activeLangLabel = computed(() => this.i18nService.activeLangLabel());

  languages = this.i18nService.availableLangs;

  toggleMenu() {
    if (this.isMenuActive()) {
      this.configService.hideMenu();
      DomHandler.unblockBodyScroll("blocked-scroll");
    } else {
      this.configService.showMenu();
      DomHandler.blockBodyScroll("blocked-scroll");
    }
  }

  toggleDarkMode() {
    this.configService.appState.update((state) => ({
      ...state,
      darkTheme: !state.darkTheme,
    }));
  }

  setLanguage(lang: AppLang) {
    this.i18nService.setLanguage(lang);
  }

  bindScrollListener() {
    if (!this.scrollListener) {
      this.scrollListener = this.renderer.listen(this.window, "scroll", () => {
        if (this.window.scrollY > 0) {
          this.el.nativeElement.children[0].classList.add("layout-topbar-sticky");
        } else {
          this.el.nativeElement.children[0].classList.remove("layout-topbar-sticky");
        }
      });
    }
  }

  unbindScrollListener() {
    if (this.scrollListener) {
      this.scrollListener();
      this.scrollListener = undefined;
    }
  }

  ngOnDestroy() {
    this.unbindScrollListener();
  }
}
