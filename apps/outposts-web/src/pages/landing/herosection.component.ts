import { AppConfigService } from '@/core/servces/app-config.service';

import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { AvatarModule } from 'primeng/avatar';
import { BadgeModule } from 'primeng/badge';
import { ButtonModule } from 'primeng/button';
import { ChartModule } from 'primeng/chart';
import { DividerModule } from 'primeng/divider';
import { DrawerModule } from 'primeng/drawer';
import { KnobModule } from 'primeng/knob';
import { OverlayBadgeModule } from 'primeng/overlaybadge';
import { ToggleSwitchModule } from 'primeng/toggleswitch';
import { TooltipModule } from 'primeng/tooltip';

@Component({
  selector: 'app-hero-section',
  standalone: true,
  imports: [
    RouterModule,
    ChartModule,
    ToggleSwitchModule,
    BadgeModule,
    FormsModule,
    DividerModule,
    AvatarModule,
    TooltipModule,
    DrawerModule,
    OverlayBadgeModule,
    KnobModule,
    ButtonModule
  ],
  template: `
        <section class="landing-hero py-20 px-20 lg:px-20">
            <div class="flex flex-col items-center">
                <h1 class="text-5xl font-bold text-center xl:text-left leading-tight">Your Personal <span class="font-bold text-primary">Digital OUTPOST</span> for Side Projects and Homelabs </h1>
                <p class="text-center mt-0 mb-20 text-surface-500 dark:text-surface-400 font-medium text-xl leading-relaxed lg:px-56">
                    Build my personal digital outpost—streamline your side projects and homelab with essential tools and features, inspired by the spirit of exploration.
                </p>
                <div class="flex items-center gap-6">
                    <a routerLink="/apps" class="linkbox linkbox-primary">
                        <span>Get Started</span>
                        <i class="pi pi-arrow-right ms-4"></i>
                    </a>
                    <a href="https://github.com/ethaxon/outposts" target="_blank" rel="noopener noreferrer" class="linkbox">
                        <span>Give a Star</span>
                        <i class="pi pi-star-fill ms-4 text-yellow-500"></i>
                    </a>
                </div>
            </div>
        </section>
    `
})
export class HeroSectionComponent {
  private configService = inject(AppConfigService);

  get isDarkMode(): boolean {
    return !!this.configService.appState().darkTheme;
  }
}
