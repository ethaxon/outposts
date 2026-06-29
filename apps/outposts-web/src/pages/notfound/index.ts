import { Component, ChangeDetectionStrategy } from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { RouterModule } from "@angular/router";
import { HlmButton } from "@/components/ui/button";

@Component({
  standalone: true,
  imports: [HlmButton, RouterModule, TranslocoModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: "./index.component.html",
})
export class NotFoundDemoComponent {}
