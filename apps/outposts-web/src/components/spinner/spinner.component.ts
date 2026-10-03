import { Component, computed, inject, ChangeDetectionStrategy } from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import { TranslocoModule } from "@jsverse/transloco";
import { HlmSpinner } from "@/components/ui/spinner";
import { AuthActivity, authActivity } from "@/domain/auth/auth-activity";
import { AppOverlayService } from "../../core/servces/app-overlay.service";

/** The single app-wide blocking overlay, for data loading and auth handoffs. */
@Component({
  selector: "app-spinner",
  standalone: true,
  templateUrl: "./spinner.component.html",
  styleUrl: "./spinner.component.scss",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [HlmSpinner, TranslocoModule],
})
export class SpinnerComponent {
  private readonly loading = toSignal(inject(AppOverlayService).loading$$, { initialValue: false });
  protected readonly signingIn = computed(() => authActivity() !== AuthActivity.Idle);
  protected readonly visible = computed(() => this.loading() || this.signingIn());
}
