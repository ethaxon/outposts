import { isPlatformBrowser } from "@angular/common";
import { Injectable, inject, PLATFORM_ID } from "@angular/core";
import { WINDOW } from "@/core/providers/window";

@Injectable({ providedIn: "root" })
export class PlatformService {
	private platformId = inject(PLATFORM_ID);
	private window = inject(WINDOW);

	isBrowser(): boolean {
		return (
			isPlatformBrowser(this.platformId) &&
			this.window !== null &&
			this.window !== undefined
		);
	}
}
