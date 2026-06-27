import { CommonModule } from "@angular/common";
import { Component, inject, ChangeDetectionStrategy } from "@angular/core";
import { ProgressSpinnerModule } from "primeng/progressspinner";
import { AppOverlayService } from "../../core/servces/app-overlay.service";

@Component({
  selector: "app-spinner",
  standalone: true,
  templateUrl: "./spinner.component.html",
  styleUrl: "./spinner.component.scss",
  changeDetection: ChangeDetectionStrategy.Eager,
  imports: [CommonModule, ProgressSpinnerModule],
})
export class SpinnerComponent {
  readonly overlayService = inject(AppOverlayService);
}
