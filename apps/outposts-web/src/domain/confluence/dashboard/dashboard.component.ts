import { Component, DestroyRef, inject, type OnInit, signal } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { switchMap } from "rxjs";
import { AppI18nService } from "@/core/servces/app-i18n.service";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import type { ConfluenceDto } from "../bindings/ConfluenceDto";
import { ConfluenceService } from "../confluence.service";

@Component({
  standalone: false,
  selector: "app-confluence-dashboard",
  templateUrl: "./dashboard.component.html",
  providers: [],
})
export class DashboardComponent implements OnInit {
  protected readonly confluenceService = inject(ConfluenceService);
  protected readonly destoryRef = inject(DestroyRef);
  protected readonly overlayService = inject(AppOverlayService);
  protected readonly i18nService = inject(AppI18nService);

  confluences = signal<ConfluenceDto[]>([]);

  ngOnInit() {
    this.overlayService
      .withSuspense(this.confluenceService.getAllConfluences())
      .pipe(takeUntilDestroyed(this.destoryRef))
      .subscribe((data) => {
        this.confluences.set(data);
      });
  }

  async addConfluence() {
    this.overlayService
      .withSuspense(
        this.confluenceService.addConfluence().pipe(
          switchMap(() => this.confluenceService.getAllConfluences()),
          takeUntilDestroyed(this.destoryRef),
        ),
      )
      .subscribe((c) => {
        this.confluences.set(c);
        this.overlayService.toast({
          severity: "success",
          summary: this.i18nService.translate("common.toast.success"),
          detail: this.i18nService.translate("confluence.dashboard.toasts.created"),
        });
      });
  }

  getSeverityKey(item: ConfluenceDto): string {
    if (item.mux_content && item.profiles.length) {
      return "confluence.dashboard.status.active";
    }
    return "confluence.dashboard.status.inactive";
  }

  getSeverity(_item: ConfluenceDto): "info" {
    return "info";
  }

  getStatusTagStyle(item: ConfluenceDto): Record<string, string> {
    if (item.mux_content && item.profiles.length) {
      return {
        background: "var(--p-green-500)",
        color: "#ffffff",
        borderColor: "transparent",
      };
    }

    return {
      background: "var(--p-surface-700)",
      color: "var(--p-surface-0)",
      borderColor: "transparent",
    };
  }

  removeConfluence(id: number) {
    this.overlayService
      .withSuspense(
        this.confluenceService.removeConfluence(id).pipe(
          switchMap(() => this.confluenceService.getAllConfluences()),
          takeUntilDestroyed(this.destoryRef),
        ),
      )
      .subscribe((c) => {
        this.confluences.set(c);
        this.overlayService.toast({
          severity: "success",
          summary: this.i18nService.translate("common.toast.success"),
          detail: this.i18nService.translate("confluence.dashboard.toasts.removed"),
        });
      });
  }
}
