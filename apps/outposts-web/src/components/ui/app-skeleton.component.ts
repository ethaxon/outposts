import { ChangeDetectionStrategy, Component, Input } from "@angular/core";
import { HlmSkeleton } from "@/components/ui/skeleton";

@Component({
  selector: "app-skeleton",
  standalone: true,
  imports: [HlmSkeleton],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<div
    hlmSkeleton
    [class.rounded-full]="shape === 'circle'"
    [style.width]="width ?? size"
    [style.height]="height ?? size"
  ></div>`,
})
export class AppSkeletonComponent {
  @Input() width?: string;
  @Input() height?: string;
  @Input() size?: string;
  @Input() shape?: "circle" | "rectangle";
}
