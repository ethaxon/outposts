import { NgClass, NgStyle } from "@angular/common";
import { TranslocoModule } from "@jsverse/transloco";
import { ChangeDetectionStrategy, Component, EventEmitter, Input, Output } from "@angular/core";
import { HlmDialogImports } from "@/components/ui/dialog";

@Component({
  selector: "app-dialog",
  standalone: true,
  imports: [NgClass, NgStyle, TranslocoModule, ...HlmDialogImports],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (visible) {
      <hlm-dialog state="open" (closed)="dismiss()">
        <hlm-dialog-content
          *hlmDialogPortal
          class="max-h-[90vh] overflow-auto sm:max-w-2xl"
          [ngClass]="styleClass"
          [ngStyle]="dialogStyle"
          [closeLabel]="'common.actions.close' | transloco"
        >
          <hlm-dialog-header>
            <h2 hlmDialogTitle>{{ header }}</h2>
          </hlm-dialog-header>
          <ng-content />
        </hlm-dialog-content>
      </hlm-dialog>
    }
  `,
})
export class AppDialogComponent {
  @Input() header = "";
  @Input() visible = false;
  @Input() modal = true;
  @Input() draggable = false;
  @Input() resizable = false;
  @Input() baseZIndex = 50;
  @Input() styleClass = "";
  @Input() style: Record<string, string> | null = null;
  @Output() readonly visibleChange = new EventEmitter<boolean>();

  get dialogStyle(): Record<string, string> {
    return {
      ...this.style,
      width: this.style?.["width"] ?? "50vw",
      minWidth: this.style?.["minWidth"] ?? "300px",
      maxWidth: this.style?.["maxWidth"] ?? "calc(100vw - 2rem)",
    };
  }

  dismiss() {
    this.visibleChange.emit(false);
  }
}
