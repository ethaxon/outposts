import { ChangeDetectionStrategy, Component, Input } from "@angular/core";
import { NgIcon } from "@ng-icons/core";
import { HlmButton } from "@/components/ui/button";

@Component({
  selector: "app-action",
  standalone: true,
  imports: [HlmButton, NgIcon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<button type="button" hlmBtn [variant]="variant" [size]="buttonSize">
    @if (icon) {
      <ng-icon [name]="icon" aria-hidden="true" />
    }
    <span>{{ label }}</span>
  </button>`,
})
export class AppActionComponent {
  @Input() label = "";
  @Input() icon = "";
  @Input() outlined = false;
  @Input() rounded = false;
  @Input() severity = "";
  @Input() size: "small" | "large" | "" = "";
  @Input() text = false;
  @Input() raised = false;

  get variant(): "default" | "outline" | "secondary" | "destructive" | "ghost" {
    if (this.outlined) return "outline";
    if (this.text) return "ghost";
    if (this.severity === "danger") return "destructive";
    if (this.severity === "secondary") return "secondary";
    return "default";
  }

  get buttonSize(): "sm" | "lg" | "default" {
    return this.size === "small" ? "sm" : this.size === "large" ? "lg" : "default";
  }
}
