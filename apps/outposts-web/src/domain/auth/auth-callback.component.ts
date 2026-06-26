import { ChangeDetectionStrategy, Component, effect, inject, viewChild } from "@angular/core";
import { Router } from "@angular/router";
import { ResourceStatus } from "@securitydept/client";
import { OidcModeCallbackHandlingKind } from "@securitydept/token-set-context-client/orchestration";
import { TokenSetFrontendCallbackComponent } from "@securitydept/token-set-context-client-angular";

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
    effect(() => {
      const state = this.callback()?.state();
      if (
        this.navigationStarted ||
        state?.status !== ResourceStatus.Resolved ||
        state.value.kind !== OidcModeCallbackHandlingKind.Handled
      ) {
        return;
      }

      this.navigationStarted = true;
      void this.router.navigateByUrl(state.value.result.postAuthRedirectUri ?? "/", {
        replaceUrl: true,
      });
    });
  }
}
