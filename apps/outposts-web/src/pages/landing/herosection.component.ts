import { Component, inject } from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { FormsModule } from "@angular/forms";
import { RouterModule } from "@angular/router";
import { AvatarModule } from "primeng/avatar";
import { BadgeModule } from "primeng/badge";
import { ButtonModule } from "primeng/button";
import { ChartModule } from "primeng/chart";
import { DividerModule } from "primeng/divider";
import { DrawerModule } from "primeng/drawer";
import { KnobModule } from "primeng/knob";
import { OverlayBadgeModule } from "primeng/overlaybadge";
import { ToggleSwitchModule } from "primeng/toggleswitch";
import { TooltipModule } from "primeng/tooltip";
import { AppConfigService } from "@/core/servces/app-config.service";

@Component({
  selector: "app-hero-section",
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
    ButtonModule,
    TranslocoModule,
  ],
  templateUrl: "./herosection.component.html",
})
export class HeroSectionComponent {
  private configService = inject(AppConfigService);

  get isDarkMode(): boolean {
    return !!this.configService.appState().darkTheme;
  }
}
