import { ChangeDetectionStrategy, Component, Input } from "@angular/core";
import { NgIcon } from "@ng-icons/core";
import { HlmButton } from "@/components/ui/button";
import { HlmSpinner } from "@/components/ui/spinner";

@Component({
  selector: "app-action",
  standalone: true,
  imports: [HlmButton, NgIcon, HlmSpinner],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<button
    [type]="type"
    hlmBtn
    [variant]="variant"
    [size]="buttonSize"
    [disabled]="disabled || loading"
    [attr.aria-busy]="loading || null"
  >
    @if (loading) {
      <hlm-spinner aria-hidden="true" />
    } @else if (icon) {
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
  /** Callers still guard their (click) handlers; a disabled button may not swallow host clicks. */
  @Input() disabled = false;
  /** Replaces the icon with a spinner and blocks repeat clicks while work is in flight. */
  @Input() loading = false;
  @Input() type: "button" | "submit" = "button";

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
