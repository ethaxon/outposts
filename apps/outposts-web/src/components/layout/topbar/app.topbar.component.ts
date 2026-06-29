import { CommonModule } from "@angular/common";
import {
  afterNextRender,
  booleanAttribute,
  Component,
  computed,
  DOCUMENT,
  ElementRef,
  HostListener,
  Input,
  inject,
  type OnDestroy,
  Renderer2,
  signal,
  ChangeDetectionStrategy,
} from "@angular/core";
import { FormsModule } from "@angular/forms";
import { TranslocoModule } from "@jsverse/transloco";
import { RouterModule } from "@angular/router";
import { NgIcon, provideIcons } from "@ng-icons/core";
import {
  lucideChevronDown,
  lucideGithub,
  lucideMenu,
  lucideMessageCircle,
  lucideMessagesSquare,
  lucideMoon,
  lucideSend,
  lucideSun,
} from "@ng-icons/lucide";
import Versions from "@/assets/data/versions.json";
import type { AppLang } from "@/app/transloco-config";
import { WINDOW } from "@/core/providers/window";
import { AppConfigService } from "@/core/servces/app-config.service";
import { AppI18nService } from "@/core/servces/app-i18n.service";

@Component({
  selector: "app-topbar",
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, TranslocoModule, NgIcon],
  providers: [
    provideIcons({
      lucideChevronDown,
      lucideGithub,
      lucideMenu,
      lucideMessageCircle,
      lucideMessagesSquare,
      lucideMoon,
      lucideSend,
      lucideSun,
    }),
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
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
  private document = inject(DOCUMENT);
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

  readonly activePanel = signal<"language" | "version" | null>(null);

  toggleMenu() {
    if (this.isMenuActive()) {
      this.configService.hideMenu();
      this.document.body.classList.remove("blocked-scroll");
    } else {
      this.configService.showMenu();
      this.document.body.classList.add("blocked-scroll");
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
    this.activePanel.set(null);
  }

  togglePanel(panel: "language" | "version") {
    this.activePanel.update((active) => (active === panel ? null : panel));
  }

  @HostListener("document:click", ["$event"])
  closePanelsOnOutsideClick(event: MouseEvent) {
    const target = event.target as Element | null;
    if (!target?.closest("[data-topbar-panel]")) {
      this.activePanel.set(null);
    }
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
