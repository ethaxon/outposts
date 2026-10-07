import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormsModule, type NgForm } from "@angular/forms";
import { TranslocoModule } from "@jsverse/transloco";
import { NgIcon, provideIcons } from "@ng-icons/core";
import {
  lucideCheck,
  lucideCircleAlert,
  lucideCloudOff,
  lucideCopy,
  lucideFilePenLine,
  lucideHouse,
  lucideKeyRound,
  lucidePlus,
  lucideRefreshCw,
  lucideTrash2,
  lucideX,
} from "@ng-icons/lucide";
import { finalize, type Observable } from "rxjs";
import { AppActionComponent } from "../../../components/ui/app-action.component";
import { AppCardComponent } from "../../../components/ui/app-card.component";
import { AppDialogComponent } from "../../../components/ui/app-dialog.component";
import { AppSkeletonComponent } from "../../../components/ui/app-skeleton.component";
import { HlmBadge } from "@/components/ui/badge";
import { HlmBreadcrumbImports } from "@/components/ui/breadcrumb";
import { HlmButton } from "@/components/ui/button";
import { HlmInputImports } from "@/components/ui/input";
import { AppI18nService } from "@/core/servces/app-i18n.service";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import { ClipboardService } from "@/tools/clipboard/clipboard.service";
import type { SupplicantSummaryDto } from "../bindings/SupplicantSummaryDto";
import type { VlanSupplicant } from "../bindings/VlanSupplicant";
import { ConfluenceService } from "../confluence.service";
import { VlanNameDirective } from "../vlans/vlan-name.directive";

type Action = "refresh" | "save" | "delete";
type ActionError = "loadError" | "saveError" | "deleteError";

@Component({
  selector: "app-supplicants-page",
  imports: [
    FormsModule,
    TranslocoModule,
    NgIcon,
    AppActionComponent,
    AppCardComponent,
    AppDialogComponent,
    AppSkeletonComponent,
    HlmBadge,
    HlmButton,
    ...HlmBreadcrumbImports,
    ...HlmInputImports,
    VlanNameDirective,
  ],
  providers: [ClipboardService],
  viewProviders: [
    provideIcons({
      lucideCheck,
      lucideCircleAlert,
      lucideCloudOff,
      lucideCopy,
      lucideFilePenLine,
      lucideHouse,
      lucideKeyRound,
      lucidePlus,
      lucideRefreshCw,
      lucideTrash2,
      lucideX,
    }),
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: "./supplicants-page.component.html",
})
export class SupplicantsPageComponent {
  private readonly service = inject(ConfluenceService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly overlay = inject(AppOverlayService);
  private readonly i18n = inject(AppI18nService);
  private readonly clipboard = inject(ClipboardService);

  readonly rows = signal<SupplicantSummaryDto[] | undefined>(undefined);
  readonly supplicants = computed(() =>
    this.rows()?.toSorted((a, b) => a.supplicant.name.localeCompare(b.supplicant.name)),
  );
  readonly editor = signal<VlanSupplicant | undefined>(undefined);
  readonly pendingDeletion = signal<string | undefined>(undefined);
  readonly action = signal<Action | undefined>(undefined);
  readonly busy = computed(() => this.action() !== undefined);
  readonly error = signal<ActionError | undefined>(undefined);
  readonly skeletons = [0, 1];
  /** Label widths for the two meta rows, so skeleton rows don't look cloned. */
  readonly skeletonRows = ["40%", "48%"];

  ngOnInit() {
    this.refresh();
  }

  refresh() {
    this.request("refresh", this.service.getSupplicants(), "loadError", (rows) => {
      this.pendingDeletion.set(undefined);
      this.rows.set(rows);
    });
  }

  editSupplicant(item?: VlanSupplicant) {
    this.error.set(undefined);
    this.pendingDeletion.set(undefined);
    this.editor.set(item ? { ...item } : { id: "", name: "", age_recipient: "" });
  }

  async copyRecipient(item: VlanSupplicant) {
    try {
      await this.clipboard.copyText(item.age_recipient);
      this.overlay.toast({
        severity: "success",
        summary: this.i18n.translate("common.toast.success"),
        detail: this.i18n.translate("common.toast.copied"),
      });
    } catch (err: unknown) {
      this.overlay.toast({
        severity: "error",
        summary: this.i18n.translate("common.toast.error"),
        detail: (err as Error)?.message,
      });
    }
  }

  closeEditor() {
    this.editor.set(undefined);
    this.error.set(undefined);
  }

  saveSupplicant(form: NgForm, item: VlanSupplicant) {
    if (form.invalid) {
      form.control.markAllAsTouched();
      return;
    }
    this.request("save", this.service.saveSupplicant(item), "saveError", (saved) => {
      this.rows.update((rows = []) => {
        const existing = rows.find((row) => row.supplicant.id === saved.id);
        return [
          ...rows.filter((row) => row !== existing),
          { ...(existing ?? { vlan_count: 0, profile_count: 0 }), supplicant: saved },
        ];
      });
      this.editor.set(undefined);
    });
  }

  deleteSupplicant(id: string) {
    this.request("delete", this.service.removeSupplicant(id), "deleteError", () => {
      this.rows.update((rows) => rows?.filter((row) => row.supplicant.id !== id));
      this.pendingDeletion.set(undefined);
    });
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
    const source = action === "refresh" ? this.overlay.withSuspense(request) : request;
    source
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.action.set(undefined)),
      )
      .subscribe({ next: success, error: () => this.error.set(error) });
  }
}
