import {
  Component,
  DestroyRef,
  inject,
  type OnInit,
  signal,
  ChangeDetectionStrategy,
} from "@angular/core";
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
  changeDetection: ChangeDetectionStrategy.OnPush,
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
    if (this.isActive(item)) {
      return "confluence.dashboard.status.active";
    }
    return "confluence.dashboard.status.inactive";
  }

  isActive(item: ConfluenceDto): boolean {
    return Boolean(item.mux_content && item.profiles.length);
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
