import Versions from '@/assets/data/versions.json';
import { AppConfigService } from '@/core/servces/app-config.service';
import { CommonModule } from '@angular/common';
import { afterNextRender, booleanAttribute, Component, computed, ElementRef, Inject, Input, OnDestroy, Renderer2, DOCUMENT } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { DomHandler } from 'primeng/dom';
import { StyleClass } from 'primeng/styleclass';

@Component({
  selector: 'app-topbar',
  standalone: true,
  imports: [CommonModule, FormsModule, StyleClass, RouterModule],
  template: `<div class="layout-topbar">
          <div class="layout-topbar-inner">
            <div class="layout-topbar-logo-container">
              <a [routerLink]="['/']" class="layout-topbar-logo" aria-label="OUTPOSTS Logo">
                <img width="150" height="30" src="image/logo-512-w.png" alt="logo"/>
              </a>
              <a [routerLink]="['/']" class="layout-topbar-icon" aria-label="OUTPOSTS Logo">
                <img width="30" height="30" src="image/logo-512.png" alt="logo" />
              </a>
            </div>

            <ul class="topbar-items">
              <li>
                <a href="https://github.com/aitiome/outposts" target="_blank" rel="noopener noreferrer" class="topbar-item">
                  <i class="pi pi-github text-surface-700 dark:text-surface-100"></i>
                </a>
              </li>
              <li>
                <a href="https://t.me/outposts_project" target="_blank" rel="noopener noreferrer" class="topbar-item">
                  <i class="pi pi-telegram text-surface-700 dark:text-surface-100"></i>
                </a>
              </li>
              <li>
                <a href="https://discord.gg/dj9teD6G" target="_blank" rel="noopener noreferrer" class="topbar-item">
                  <i class="pi pi-discord text-surface-700 dark:text-surface-100"></i>
                </a>
              </li>
              <li>
                <a href="https://github.com/aitiome/outposts/discussions" target="_blank" rel="noopener noreferrer" class="topbar-item">
                  <i class="pi pi-comments text-surface-700 dark:text-surface-100"></i>
                </a>
              </li>
              <li>
                <button type="button" class="topbar-item" (click)="toggleDarkMode()">
                  <i class="pi" [ngClass]="{ 'pi-moon': isDarkMode(), 'pi-sun': !isDarkMode() }"></i>
                </button>
              </li>
              <li>
                <button pStyleClass="@next" enterFromClass="hidden" enterActiveClass="animate-scalein" leaveToClass="hidden" leaveActiveClass="animate-fadeout" [hideOnOutsideClick]="true" type="button" class="topbar-item version-item">
                  <span class="version-text">{{ versions ? versions[0].name : 'Latest' }}</span>
                  <span class="version-icon pi pi-angle-down"></span>
                </button>
                <div class="versions-panel hidden">
                  <ul>
                    @for (v of versions; track v) {
                      <li role="none">
                        <a [href]="v.url">
                          <span>{{ v.version }}</span>
                        </a>
                      </li>
                    }
                  </ul>
                </div>
              </li>
              @if (showMenuButton) {
                <li class="menu-button">
                  <button type="button" class="topbar-item menu-button" (click)="toggleMenu()" aria-label="Menu">
                    <i class="pi pi-bars"></i>
                  </button>
                </li>
              }
            </ul>
          </div>
        </div>`
})
export class AppTopBarComponent implements OnDestroy {
  @Input({ transform: booleanAttribute }) showConfigurator = true;

  @Input({ transform: booleanAttribute }) showMenuButton = true;

  versions: any[] = Versions;

  scrollListener?: VoidFunction;

  private window: Window;

  constructor(
    @Inject(DOCUMENT) private document: Document,
    private el: ElementRef,
    private renderer: Renderer2,
    private configService: AppConfigService
  ) {
    this.window = this.document.defaultView as Window;

    afterNextRender(() => {
      this.bindScrollListener();
    });
  }

  isDarkMode = computed(() => this.configService.appState().darkTheme);

  isMenuActive = computed(() => this.configService.appState().menuActive);

  toggleMenu() {
    if (this.isMenuActive()) {
      this.configService.hideMenu();
      DomHandler.unblockBodyScroll('blocked-scroll');
    } else {
      this.configService.showMenu();
      DomHandler.blockBodyScroll('blocked-scroll');
    }
  }

  toggleDarkMode() {
    this.configService.appState.update((state) => ({ ...state, darkTheme: !state.darkTheme }));
  }

  bindScrollListener() {
    if (!this.scrollListener) {
      this.scrollListener = this.renderer.listen(this.window, 'scroll', () => {
        if (this.window.scrollY > 0) {
          this.el.nativeElement.children[0].classList.add('layout-topbar-sticky');
        } else {
          this.el.nativeElement.children[0].classList.remove('layout-topbar-sticky');
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
