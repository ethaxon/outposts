import { Component, DestroyRef, inject } from "@angular/core";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import { AuthService } from "./auth.service";

@Component({
	selector: "app-auth-callback",
	template: ``,
	providers: [],
})
export class AuthCallbackComponent {
	protected readonly authService = inject(AuthService);
	protected readonly destoryRef = inject(DestroyRef);
	protected readonly overlayService = inject(AppOverlayService);
}
