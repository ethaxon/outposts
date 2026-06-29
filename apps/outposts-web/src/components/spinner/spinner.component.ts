import { CommonModule } from "@angular/common";
import { Component, inject, ChangeDetectionStrategy } from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { HlmSpinner } from "@/components/ui/spinner";
import { AppOverlayService } from "../../core/servces/app-overlay.service";

@Component({
  selector: "app-spinner",
  standalone: true,
  templateUrl: "./spinner.component.html",
  styleUrl: "./spinner.component.scss",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule, HlmSpinner, TranslocoModule],
})
export class SpinnerComponent {
  readonly overlayService = inject(AppOverlayService);
}
