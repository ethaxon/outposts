import {
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  input,
  output,
  signal,
  type OnInit,
} from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormsModule } from "@angular/forms";
import { TranslocoModule } from "@jsverse/transloco";
import { finalize, type Observable } from "rxjs";
import { NgIcon, provideIcons } from "@ng-icons/core";
import {
  lucideCheck,
  lucideFilePenLine,
  lucidePlus,
  lucideRefreshCw,
  lucideTrash2,
} from "@ng-icons/lucide";
import { AppActionComponent } from "../../../components/ui/app-action.component";
import { AppCardComponent } from "../../../components/ui/app-card.component";
import { AppDialogComponent } from "../../../components/ui/app-dialog.component";
import { HlmButton } from "@/components/ui/button";
import { HlmInputImports } from "@/components/ui/input";
import type { UUIDV7 } from "../bindings/UUIDV7";
import type { VlanConfig } from "../bindings/VlanConfig";
import type { VlanNetwork } from "../bindings/VlanNetwork";
import type { VlanSupplicant } from "../bindings/VlanSupplicant";
import { ConfluenceService } from "../confluence.service";
import { VlanEditorComponent } from "./vlan-editor.component";

type Editor =
  | { kind: "network"; item?: VlanNetwork }
  | { kind: "supplicant"; item: VlanSupplicant };

@Component({
  selector: "app-vlan-catalog",
  imports: [
    FormsModule,
    TranslocoModule,
    NgIcon,
    AppActionComponent,
    AppCardComponent,
    AppDialogComponent,
    HlmButton,
    ...HlmInputImports,
    VlanEditorComponent,
  ],
  templateUrl: "./vlan-catalog.component.html",
  styleUrl: "./vlan-catalog.component.scss",
  // The /vlans route renders this component standalone, so it provides its own icons.
  viewProviders: [
    provideIcons({ lucideCheck, lucideFilePenLine, lucidePlus, lucideRefreshCw, lucideTrash2 }),
  ],
})
export class VlanCatalogComponent implements OnInit {
  private readonly service = inject(ConfluenceService);
  private readonly destroyRef = inject(DestroyRef);
  readonly workspaceId = input<UUIDV7>();
  readonly vlanIds = input<UUIDV7[]>([]);
  readonly referencesSaved = output<UUIDV7[]>();

  readonly catalog = signal<VlanConfig | undefined>(undefined);
  readonly selected = signal<ReadonlySet<UUIDV7>>(new Set());
  readonly editor = signal<Editor | undefined>(undefined);
  readonly pendingDeletion = signal<string | undefined>(undefined);
  readonly busy = signal(false);
  readonly error = signal("");
  readonly dirty = computed(() => {
    const saved = this.vlanIds();
    const selected = this.selected();
    return saved.length !== selected.size || saved.some((id) => !selected.has(id));
  });

  constructor() {
    effect(() => {
      this.workspaceId();
      this.selected.set(new Set(this.vlanIds()));
    });
  }

  ngOnInit() {
    this.refresh();
  }

  refresh() {
    this.request(
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

  saveReferences() {
    const id = this.workspaceId();
    if (!id) return;
    this.request(
      this.service.updateWorkspaceVlans(id, { vlan_ids: [...this.selected()] }),
      (ids) => {
        this.selected.set(new Set(ids));
        this.referencesSaved.emit(ids);
      },
    );
  }

  editNetwork(item?: VlanNetwork) {
    this.editor.set({ kind: "network", item });
  }

  editSupplicant(item?: VlanSupplicant) {
    this.error.set("");
    this.editor.set({
      kind: "supplicant",
      item: item ? { ...item } : { id: "", name: "", age_recipient: "" },
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

  saveSupplicant(item: VlanSupplicant) {
    this.request(this.service.saveSupplicant(item), (saved) => {
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
    return (
      this.catalog()?.vlan_configs.some((vlan) =>
        vlan.accept_supplicants.some((grant) => grant.supplicant_id === id),
      ) ?? false
    );
  }

  deleteNetwork(id: UUIDV7) {
    this.request(this.service.removeVlan(id), () => {
      this.catalog.update(
        (data) =>
          data && {
            ...data,
            vlan_configs: data.vlan_configs.filter((network) => network.id !== id),
          },
      );
      this.pendingDeletion.set(undefined);
    });
  }

  deleteSupplicant(id: UUIDV7) {
    this.request(this.service.removeSupplicant(id), () => {
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

  private request<T>(request: Observable<T>, success: (result: T) => void, errorKey = "saveError") {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set("");
    request
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: success,
        error: () => this.error.set(errorKey),
      });
  }
}
