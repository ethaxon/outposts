import { DestroyRef, Injectable, inject } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { TOKEN_SET_CLIENT_REGISTRY } from "@securitydept/token-set-context-client-angular";
import { from } from "rxjs";
import { AppOverlayService } from "@/core/servces/app-overlay.service";

/** Owns Outposts-specific auth orchestration that does not belong in the SDK. */
@Injectable()
export class AuthService {
  private readonly destroyRef = inject(DestroyRef);
  private readonly registry = inject(TOKEN_SET_CLIENT_REGISTRY);
  private readonly appOverlayService = inject(AppOverlayService);
  private started = false;

  /** Starts all root-scoped Outposts auth orchestration exactly once. */
  start(): void {
    if (this.started) {
      return;
    }
    this.started = true;

    from(this.registry.errors)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((error) => this.appOverlayService.showClientError(error));
  }
}
