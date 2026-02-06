import { Component, DestroyRef, inject } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { TranslocoService } from "@jsverse/transloco";
import { take } from "rxjs/operators";
import { AppOverlayService } from "@/core/servces/app-overlay.service";

@Component({
	standalone: false,
	selector: "app-doc-section-clipboard-button",
	template: `
    <p-button
      icon="pi pi-copy"
      severity="secondary"
      (click)="onClick()"
    ></p-button>
  `,
})
export class DocClipboardButtonComponent {
	private readonly overlayService = inject(AppOverlayService);
	private readonly t = inject(TranslocoService);
	private readonly destroyRef = inject(DestroyRef);

	onClick() {
		this.t
			.selectTranslateObject<{ title: string; detail: string }>(
				"layout-section.clipboard_copied_toast",
			)
			.pipe(take(1), takeUntilDestroyed(this.destroyRef))
			.subscribe((translation) => {
				this.overlayService.toast({
					severity: "success",
					summary: translation.title,
					detail: translation.detail,
				});
			});
	}
}
