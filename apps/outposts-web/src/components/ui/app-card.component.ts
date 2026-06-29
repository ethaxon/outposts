import { ChangeDetectionStrategy, Component } from "@angular/core";
import { HlmCard, HlmCardContent } from "@/components/ui/card";

@Component({
  selector: "app-card",
  standalone: true,
  imports: [HlmCard, HlmCardContent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: "block" },
  template: `<article hlmCard class="h-full" style="--card-spacing: 1.25rem">
    <div hlmCardContent><ng-content /></div>
  </article>`,
})
export class AppCardComponent {}
