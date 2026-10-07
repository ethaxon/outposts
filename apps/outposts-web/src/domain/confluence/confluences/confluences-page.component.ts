import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  type OnInit,
  computed,
  inject,
  signal,
} from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { RouterLink } from "@angular/router";
import { TranslocoModule } from "@jsverse/transloco";
import { NgIcon } from "@ng-icons/core";
import { finalize, switchMap, type Observable } from "rxjs";
import { HlmBadge } from "@/components/ui/badge";
import { HlmBreadcrumbImports } from "@/components/ui/breadcrumb";
import { HlmButton } from "@/components/ui/button";
import { HlmSkeleton } from "@/components/ui/skeleton";
import { AppI18nService } from "@/core/servces/app-i18n.service";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import type { ConfluenceDto } from "../bindings/ConfluenceDto";
import { AppActionComponent } from "../../../components/ui/app-action.component";
import { AppCardComponent } from "../../../components/ui/app-card.component";
import { ConfluenceService } from "../confluence.service";

type Action = "refresh" | "create" | "delete";
type ActionError = "loadError" | "createError" | "deleteError";

/** `/confluence/confluences`: the Confluence catalog, styled like the VLAN and supplicant pages. */
@Component({
  selector: "app-confluences-page",
  imports: [
    RouterLink,
    TranslocoModule,
    NgIcon,
    HlmBadge,
    HlmButton,
    ...HlmBreadcrumbImports,
    HlmSkeleton,
    AppActionComponent,
    AppCardComponent,
  ],
  templateUrl: "./confluences-page.component.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ConfluencesPageComponent implements OnInit {
  private readonly confluenceService = inject(ConfluenceService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly overlayService = inject(AppOverlayService);
  private readonly i18nService = inject(AppI18nService);

  /** `undefined` until the first successful load, which drives the skeleton cards. */
  readonly rows = signal<ConfluenceDto[] | undefined>(undefined);
  /** Oldest first, so a newly created Confluence appends instead of reshuffling the grid. */
  readonly confluences = computed(() =>
    this.rows()?.toSorted((a, b) => a.created_at - b.created_at || a.name.localeCompare(b.name)),
  );
  readonly pendingDeletion = signal<string | undefined>(undefined);
  readonly action = signal<Action | undefined>(undefined);
  readonly busy = computed(() => this.action() !== undefined);
  readonly error = signal<ActionError | undefined>(undefined);
  readonly skeletons = [0, 1, 2];
  /** Label widths for the four meta rows, so skeleton rows don't look cloned. */
  readonly skeletonRows = ["38%", "30%", "34%", "26%"];

  ngOnInit() {
    this.refresh();
  }

  refresh() {
    this.request("refresh", this.confluenceService.getAllConfluences(), "loadError", (rows) => {
      this.pendingDeletion.set(undefined);
      this.rows.set(rows);
    });
  }

  addConfluence() {
    this.request(
      "create",
      this.confluenceService
        .addConfluence()
        .pipe(switchMap(() => this.confluenceService.getAllConfluences())),
      "createError",
      (rows) => {
        this.rows.set(rows);
        this.toastSuccess("confluence.confluences.toasts.created");
      },
    );
  }

  removeConfluence(id: string) {
    this.request("delete", this.confluenceService.removeConfluence(id), "deleteError", () => {
      this.rows.update((rows) => rows?.filter((row) => row.id !== id));
      this.pendingDeletion.set(undefined);
      this.toastSuccess("confluence.confluences.toasts.removed");
    });
  }

  isActive(item: ConfluenceDto): boolean {
    return Boolean(item.mux_content && item.profiles.length);
  }

  private request<T>(
    action: Action,
    request: Observable<T>,
    error: ActionError,
    success: (result: T) => void,
  ) {
    if (this.busy()) return;
    this.action.set(action);
    this.error.set(undefined);
    // Only page loads use the app-wide suspense; card actions show their own spinners.
    const source = action === "refresh" ? this.overlayService.withSuspense(request) : request;
    source
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.action.set(undefined)),
      )
      .subscribe({ next: success, error: () => this.error.set(error) });
  }

  private toastSuccess(detailKey: string) {
    this.overlayService.toast({
      severity: "success",
      summary: this.i18nService.translate("common.toast.success"),
      detail: this.i18nService.translate(detailKey),
    });
  }
}
