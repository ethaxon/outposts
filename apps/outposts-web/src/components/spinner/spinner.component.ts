import { Component, inject } from '@angular/core';
import { AppOverlayService } from '../../core/servces/app-overlay.service';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-spinner',
  standalone: true,
  template: `
    @if (overlayService.loading$$ | async) {
    <div
      class="fullscreen-spinner flex justify-center items-center"
    >
      <p-progressSpinner
        class="w-16 h-16"
        strokeWidth="8"
        fill="var(--surface-ground)"
        animationDuration=".5s"
        fill="transparent"
      ></p-progressSpinner>
    </div>
    }
  `,
  styles: `
.fullscreen-spinner {
  position: fixed;
  width: 100%;
  min-height: 100vh;
  left: 0;
  right: 0;
  top: 0;
  bottom: 0;
  background-color: rgba(255, 255, 255, 0.5);
  z-index: 9999;
}
  `,
  imports: [CommonModule, ProgressSpinnerModule],
})
export class SpinnerComponent {
  readonly overlayService = inject(AppOverlayService);
}
