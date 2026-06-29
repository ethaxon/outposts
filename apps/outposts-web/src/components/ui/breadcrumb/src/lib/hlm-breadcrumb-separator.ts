import { ChangeDetectionStrategy, Component } from "@angular/core";
import { NgIcon, provideIcons } from "@ng-icons/core";
import { lucideChevronRight } from "@ng-icons/lucide";
import { classes } from "@/components/ui/utils";

@Component({
  selector: "[hlmBreadcrumbSeparator]",
  imports: [NgIcon],
  providers: [provideIcons({ lucideChevronRight })],
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    "data-slot": "breadcrumb-separator",
    role: "presentation",
    "aria-hidden": "true",
  },
  template: `
    <ng-content>
      <ng-icon name="lucideChevronRight" />
    </ng-content>
  `,
})
export class HlmBreadcrumbSeparator {
  constructor() {
    classes(() => "[&>ng-icon]:text-[length:--spacing(3.5)] [&>ng-icon]:flex");
  }
}
