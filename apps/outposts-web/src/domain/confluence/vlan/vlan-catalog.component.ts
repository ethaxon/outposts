import {
  Component,
  DestroyRef,
  computed,
  inject,
  input,
  linkedSignal,
  output,
  signal,
  type OnInit,
} from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormsModule, type NgForm } from "@angular/forms";
import { TranslocoModule } from "@jsverse/transloco";
import { NgIcon, provideIcons } from "@ng-icons/core";
import {
  lucideCheck,
  lucideCircleAlert,
  lucideCloudOff,
  lucideFilePenLine,
  lucideKeyRound,
  lucideNetwork,
  lucidePlus,
  lucideRefreshCw,
  lucideShieldCheck,
  lucideTrash2,
  lucideX,
} from "@ng-icons/lucide";
import { finalize, type Observable } from "rxjs";
import { AppActionComponent } from "../../../components/ui/app-action.component";
import { AppCardComponent } from "../../../components/ui/app-card.component";
import { AppDialogComponent } from "../../../components/ui/app-dialog.component";
import { AppSkeletonComponent } from "../../../components/ui/app-skeleton.component";
import { HlmBadge } from "@/components/ui/badge";
import { HlmButton } from "@/components/ui/button";
import { HlmCheckboxImports } from "@/components/ui/checkbox";
import { HlmInputImports } from "@/components/ui/input";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import type { UUIDV7 } from "../bindings/UUIDV7";
import type { VlanConfig } from "../bindings/VlanConfig";
import type { VlanNetwork } from "../bindings/VlanNetwork";
import type { VlanSupplicant } from "../bindings/VlanSupplicant";
import { ConfluenceService } from "../confluence.service";
import { VlanEditorComponent } from "./vlan-editor.component";
import { VlanNameDirective } from "./vlan-name.directive";

type Editor =
  | { kind: "network"; item?: VlanNetwork }
  | { kind: "supplicant"; item: VlanSupplicant; isNew: boolean };

/** Which request is in flight, so only the control that started it shows a spinner. */
type Action = "refresh" | "references" | "supplicant" | "delete";

@Component({
  selector: "app-vlan-catalog",
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
    ...HlmCheckboxImports,
    ...HlmInputImports,
    VlanEditorComponent,
    VlanNameDirective,
  ],
  templateUrl: "./vlan-catalog.component.html",
  styleUrl: "./vlan-catalog.component.scss",
  // Also rendered by the /vlans page outside the module's declarations, so it provides its own icons.
  viewProviders: [
    provideIcons({
      lucideCheck,
      lucideCircleAlert,
      lucideCloudOff,
      lucideFilePenLine,
      lucideKeyRound,
      lucideNetwork,
      lucidePlus,
      lucideRefreshCw,
      lucideShieldCheck,
      lucideTrash2,
      lucideX,
    }),
  ],
})
export class VlanCatalogComponent implements OnInit {
  private readonly service = inject(ConfluenceService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly overlay = inject(AppOverlayService);
  readonly workspaceId = input<UUIDV7>();
  readonly vlanIds = input<UUIDV7[]>([]);
  readonly referencesSaved = output<UUIDV7[]>();

  readonly catalog = signal<VlanConfig | undefined>(undefined);
  // Local draft of the workspace links, reset whenever the saved links or workspace change.
  readonly selected = linkedSignal<ReadonlySet<UUIDV7>>(() => {
    this.workspaceId();
    return new Set(this.vlanIds());
  });
  readonly editor = signal<Editor | undefined>(undefined);
  readonly pendingDeletion = signal<string | undefined>(undefined);
  readonly action = signal<Action | undefined>(undefined);
  readonly busy = computed(() => this.action() !== undefined);
  readonly error = signal("");
  readonly dirty = computed(() => {
    const saved = this.vlanIds();
    const selected = this.selected();
    return saved.length !== selected.size || saved.some((id) => !selected.has(id));
  });
  /** Stable order: the API appends edits to the end, which would make cards jump. */
  readonly networks = computed(() =>
    [...(this.catalog()?.vlan_configs ?? [])].sort((a, b) => a.network.localeCompare(b.network)),
  );
  readonly supplicants = computed(() =>
    [...(this.catalog()?.supplicant_configs ?? [])].sort((a, b) => a.name.localeCompare(b.name)),
  );
  readonly skeletons = [0, 1];
  /** Label widths for the three meta rows, so skeleton rows don't look cloned. */
  readonly skeletonRows = ["45%", "38%", "30%"];

  ngOnInit() {
    this.refresh();
  }

  refresh() {
    this.request(
      "refresh",
      this.service.getVlanCatalog(),
      (data) => {
        this.catalog.set(data);
        const available = new Set(data.vlan_configs.map((network) => network.id));
        this.selected.update((ids) => new Set([...ids].filter((id) => available.has(id))));
      },
      "loadError",
    );
  }

  select(id: UUIDV7, checked: boolean) {
    this.selected.update((ids) => {
      const next = new Set(ids);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  toggleSelection(id: UUIDV7) {
    if (this.workspaceId() && !this.busy()) this.select(id, !this.selected().has(id));
  }

  saveReferences() {
    const id = this.workspaceId();
    if (!id || !this.dirty()) return;
    this.request(
      "references",
      this.service.updateWorkspaceVlans(id, { vlan_ids: [...this.selected()] }),
      (ids) => {
        this.selected.set(new Set(ids));
        this.referencesSaved.emit(ids);
      },
    );
  }

  editNetwork(item?: VlanNetwork) {
    this.error.set("");
    this.editor.set({ kind: "network", item });
  }

  editSupplicant(item?: VlanSupplicant) {
    this.error.set("");
    this.editor.set({
      kind: "supplicant",
      item: item ? { ...item } : { id: "", name: "", age_recipient: "" },
      isNew: !item,
    });
  }

  closeEditor() {
    this.editor.set(undefined);
    this.error.set("");
  }

  networkSaved(network: VlanNetwork) {
    const editor = this.editor();
    this.catalog.update(
      (data) =>
        data && {
          ...data,
          vlan_configs: [...data.vlan_configs.filter((item) => item.id !== network.id), network],
        },
    );
    if (this.workspaceId() && editor?.kind === "network" && !editor.item)
      this.select(network.id, true);
    this.closeEditor();
  }

  submitSupplicant(form: NgForm, item: VlanSupplicant) {
    if (form.invalid) {
      form.control.markAllAsTouched();
      return;
    }
    this.saveSupplicant(item);
  }

  saveSupplicant(item: VlanSupplicant) {
    this.request("supplicant", this.service.saveSupplicant(item), (saved) => {
      this.catalog.update(
        (data) =>
          data && {
            ...data,
            supplicant_configs: [
              ...data.supplicant_configs.filter((identity) => identity.id !== saved.id),
              saved,
            ],
          },
      );
      this.closeEditor();
    });
  }

  isGranted(id: string) {
    return this.membershipCount(id) > 0;
  }

  membershipCount(id: string) {
    return (
      this.catalog()?.vlan_configs.filter((vlan) =>
        vlan.accept_supplicants.some((grant) => grant.supplicant_id === id),
      ).length ?? 0
    );
  }

  tunnelTypes(network: VlanNetwork) {
    return {
      portals: network.tunnels.filter((tunnel) => tunnel.type === "easytier-gateway").length,
      wireguard: network.tunnels.filter((tunnel) => tunnel.type === "wireguard-compatible").length,
    };
  }

  /** age recipients are long bech32 strings; the ends are what people compare. */
  shortRecipient(recipient: string) {
    return recipient.length > 20 ? `${recipient.slice(0, 10)}…${recipient.slice(-6)}` : recipient;
  }

  deleteNetwork(id: UUIDV7) {
    this.request("delete", this.service.removeVlan(id), () => {
      this.catalog.update(
        (data) =>
          data && {
            ...data,
            vlan_configs: data.vlan_configs.filter((network) => network.id !== id),
          },
      );
      this.select(id, false);
      this.pendingDeletion.set(undefined);
    });
  }

  deleteSupplicant(id: UUIDV7) {
    this.request("delete", this.service.removeSupplicant(id), () => {
      this.catalog.update(
        (data) =>
          data && {
            ...data,
            supplicant_configs: data.supplicant_configs.filter((identity) => identity.id !== id),
          },
      );
      this.pendingDeletion.set(undefined);
    });
  }

  private request<T>(
    action: Action,
    request: Observable<T>,
    success: (result: T) => void,
    errorKey = "saveError",
  ) {
    if (this.busy()) return;
    this.action.set(action);
    this.error.set("");
    // Standalone loads use the app-wide suspense (overlay spinner + error toast) like
    // the dashboard. Embedded in a workspace, that page already drives the overlay and
    // `loading$$` is a shared boolean, so a second suspense would end it early.
    const suspend = action === "refresh" && !this.workspaceId();
    const source = suspend ? this.overlay.withSuspense(request) : request;
    source
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.action.set(undefined)),
      )
      .subscribe({
        next: success,
        error: () => this.error.set(errorKey),
      });
  }
}
