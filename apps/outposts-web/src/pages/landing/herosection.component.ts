import { Component, ChangeDetectionStrategy } from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { RouterModule } from "@angular/router";
import { NgIcon, provideIcons } from "@ng-icons/core";
import { lucideArrowRight, lucideStar } from "@ng-icons/lucide";

@Component({
  selector: "app-hero-section",
  standalone: true,
  imports: [RouterModule, TranslocoModule, NgIcon],
  providers: [provideIcons({ lucideArrowRight, lucideStar })],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: "./herosection.component.html",
})
export class HeroSectionComponent {}
