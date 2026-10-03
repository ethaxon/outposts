import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  effect,
  inject,
  viewChild,
} from "@angular/core";
import { Router } from "@angular/router";
import { ResourceStatus } from "@securitydept/client";
import { OidcModeCallbackHandlingKind } from "@securitydept/token-set-context-client/orchestration";
import { TokenSetFrontendCallbackComponent } from "@securitydept/token-set-context-client-angular";
import { AuthActivity, clearAuthActivity, setAuthActivity } from "./auth-activity";

/** Hosts SDK callback handling while keeping post-auth routing app-owned. */
@Component({
  selector: "app-auth-callback",
  standalone: true,
  imports: [TokenSetFrontendCallbackComponent],
  template: `<sd-token-set-frontend-callback />`,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AuthCallbackComponent {
  private readonly callback = viewChild(TokenSetFrontendCallbackComponent);
  private readonly router = inject(Router);
  private navigationStarted = false;

  constructor() {
    // The callback is in progress from the moment this route renders.
    setAuthActivity(AuthActivity.Callback);
    inject(DestroyRef).onDestroy(() => clearAuthActivity(AuthActivity.Callback));

    effect(() => {
      const state = this.callback()?.state();
      if (this.navigationStarted || !state) return;

      if (
        state.status === ResourceStatus.Resolved &&
        state.value.kind === OidcModeCallbackHandlingKind.Handled
      ) {
        this.navigationStarted = true;
        // Keep the sign-in overlay until the post-auth route is active; if that
        // route redirects to the IdP again, the redirect state takes over instead.
        void this.router
          .navigateByUrl(state.value.result.postAuthRedirectUri ?? "/", { replaceUrl: true })
          .finally(() => clearAuthActivity(AuthActivity.Callback));
      } else if (
        state.status !== ResourceStatus.Idle &&
        state.status !== ResourceStatus.Loading &&
        state.status !== ResourceStatus.Reloading
      ) {
        // Failed or not applicable: let the SDK component's outcome show through.
        clearAuthActivity(AuthActivity.Callback);
      }
    });
  }
}
