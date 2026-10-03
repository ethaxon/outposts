import { DestroyRef, Injectable, inject } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { TOKEN_SET_CLIENT_REGISTRY } from "@securitydept/token-set-context-client-angular";
import { from, fromEvent } from "rxjs";
import { WINDOW } from "@/core/providers/window";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import { AuthActivity, clearAuthActivity } from "./auth-activity";

/** Owns Outposts-specific auth orchestration that does not belong in the SDK. */
@Injectable()
export class AuthService {
  private readonly destroyRef = inject(DestroyRef);
  private readonly registry = inject(TOKEN_SET_CLIENT_REGISTRY);
  private readonly appOverlayService = inject(AppOverlayService);
  private readonly window = inject(WINDOW);
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

    // Going back from the IdP restores this page from bfcache with the redirect
    // still marked; the user abandoned it, so stop showing the sign-in overlay.
    fromEvent<PageTransitionEvent>(this.window, "pageshow")
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((event) => {
        if (event.persisted) clearAuthActivity(AuthActivity.Redirecting);
      });
  }
}
