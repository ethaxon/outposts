import { NgTemplateOutlet } from "@angular/common";
import {
  Component,
  DestroyRef,
  ElementRef,
  inject,
  input,
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
  lucideFileDown,
  lucideInfo,
  lucideNetwork,
  lucidePlus,
  lucideRefreshCw,
  lucideShieldCheck,
  lucideTrash2,
  lucideX,
} from "@ng-icons/lucide";
import { finalize } from "rxjs";
import { v7 as uuidv7 } from "uuid";
import { AppActionComponent } from "../../../components/ui/app-action.component";
import { HlmBadge } from "@/components/ui/badge";
import { HlmButton } from "@/components/ui/button";
import { HlmInputImports } from "@/components/ui/input";
import { HlmSpinner } from "@/components/ui/spinner";
import { HlmSwitchImports } from "@/components/ui/switch";
import type { VlanNetwork } from "../bindings/VlanNetwork";
import type { VlanSupplicant } from "../bindings/VlanSupplicant";
import type { VlanTunnel } from "../bindings/VlanTunnel";
import type { WireGuardClientConfig } from "../bindings/WireGuardClientConfig";
import { ConfluenceService } from "../confluence.service";
import { CidrListInputComponent } from "./cidr-list-input.component";
import { CidrDirective } from "./cidr.directive";
import { VlanNameDirective } from "./vlan-name.directive";
import { parseWireGuardClient, parseWireGuardImport } from "./wireguard-import";

type Portal = Extract<VlanTunnel, { type: "easytier-gateway" }>;
type WireGuardTunnel = Extract<VlanTunnel, { type: "wireguard-compatible" }>;
type ImportTarget = Portal | WireGuardClientConfig;

/** A destructive draft change waiting for an inline confirmation. */
type PendingRemoval =
  | { kind: "member"; id: string }
  | { kind: "config"; tunnel: WireGuardTunnel; config: WireGuardClientConfig }
  | { kind: "tunnel"; tunnel: VlanTunnel };

const REVIEW_NOTICES = new Set(["reviewPortal", "reviewClient", "wildcard"]);

@Component({
  selector: "app-vlan-editor",
  imports: [
    FormsModule,
    NgTemplateOutlet,
    TranslocoModule,
    NgIcon,
    AppActionComponent,
    HlmBadge,
    HlmButton,
    ...HlmInputImports,
    HlmSpinner,
    ...HlmSwitchImports,
    CidrListInputComponent,
    CidrDirective,
    VlanNameDirective,
  ],
  templateUrl: "./vlan-editor.component.html",
  styleUrl: "./vlan-editor.component.scss",
  viewProviders: [
    provideIcons({
      lucideCheck,
      lucideCircleAlert,
      lucideFileDown,
      lucideInfo,
      lucideNetwork,
      lucidePlus,
      lucideRefreshCw,
      lucideShieldCheck,
      lucideTrash2,
      lucideX,
    }),
  ],
})
export class VlanEditorComponent implements OnInit {
  private readonly destroyRef = inject(DestroyRef);
  private readonly service = inject(ConfluenceService);
  // Optional so the editor logic can be unit-tested without a rendered host.
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef, { optional: true });
  readonly initial = input<VlanNetwork>();
  readonly identities = input.required<VlanSupplicant[]>();
  readonly saved = output<VlanNetwork>();
  readonly cancelled = output<void>();
  readonly busy = signal(false);
  readonly error = signal(false);
  readonly recalculating = signal(false);
  /** Set once the user tried to save, so every blocking problem becomes visible. */
  readonly attempted = signal(false);
  /** The import panel that is open; notices stay attached to the tunnel they came from. */
  readonly importing = signal<ImportTarget | null>(null);
  readonly importNotice = signal<{ target: ImportTarget; key: string } | undefined>(undefined);
  readonly pendingRemoval = signal<PendingRemoval | null>(null);

  network: VlanNetwork = {
    id: "",
    enabled: false,
    network: "",
    routes: [],
    tunnels: [],
    accept_supplicants: [],
  };

  get supplicants() {
    return this.identities();
  }

  get members() {
    return this.supplicants.filter((identity) => this.isMember(identity.id));
  }

  ngOnInit() {
    const initial = this.initial();
    if (initial) this.network = structuredClone(initial);
  }

  // Members

  isMember(id: string) {
    return this.network.accept_supplicants.some((member) => member.supplicant_id === id);
  }

  toggleMember(id: string) {
    if (!this.isMember(id)) {
      this.network.accept_supplicants.push({ supplicant_id: id });
    } else if (this.memberGrantCount(id)) {
      this.pendingRemoval.set({ kind: "member", id });
    } else {
      this.removeMember(id);
    }
  }

  get availableMembers() {
    return this.supplicants.filter((identity) => !this.isMember(identity.id));
  }

  labelMember(id: string) {
    return this.supplicants.find((identity) => identity.id === id)?.name ?? id;
  }

  memberGrantCount(id: string) {
    return this.network.tunnels.filter((tunnel) =>
      tunnel.grants.some((grant) => grant.supplicant_id === id),
    ).length;
  }

  removeMember(id: string) {
    this.network.accept_supplicants = this.network.accept_supplicants.filter(
      (member) => member.supplicant_id !== id,
    );
    for (const tunnel of this.network.tunnels) {
      const index = tunnel.grants.findIndex((grant) => grant.supplicant_id === id);
      if (index >= 0) tunnel.grants.splice(index, 1);
    }
    this.pendingRemoval.set(null);
  }

  // Tunnels

  addTunnel(type: VlanTunnel["type"]) {
    const common = { id: "", name: "", grants: [] };
    this.network.tunnels.push(
      type === "easytier-gateway"
        ? {
            ...common,
            type,
            server: "",
            port: 24,
            subnet: "",
            allowed_ips: [],
            has_private_key: false,
          }
        : { ...common, type, configs: [] },
    );
  }

  requestRemoveTunnel(tunnel: VlanTunnel) {
    if (
      tunnel.id ||
      tunnel.grants.length ||
      (tunnel.type === "wireguard-compatible" && tunnel.configs.length)
    ) {
      this.pendingRemoval.set({ kind: "tunnel", tunnel });
    } else {
      this.removeTunnel(tunnel);
    }
  }

  removeTunnel(tunnel: VlanTunnel) {
    this.network.tunnels = this.network.tunnels.filter((item) => item !== tunnel);
    this.pendingRemoval.set(null);
  }

  hasGrant(tunnel: VlanTunnel, id: string) {
    return tunnel.grants.some((grant) => grant.supplicant_id === id);
  }

  togglePortalGrant(tunnel: Portal, id: string) {
    const index = tunnel.grants.findIndex((grant) => grant.supplicant_id === id);
    if (index >= 0) {
      tunnel.grants.splice(index, 1);
    } else if (this.isMember(id)) {
      tunnel.grants.push({ supplicant_id: id, slots: "2-254" });
    }
  }

  addWireGuardConfig(tunnel: WireGuardTunnel) {
    tunnel.configs.push({
      id: uuidv7(),
      addresses: [""],
      mtu: null,
      persistent_keepalive: null,
      has_private_key: false,
      peers: [],
    });
  }

  wireGuardAssignee(tunnel: WireGuardTunnel, config: WireGuardClientConfig) {
    return tunnel.grants.find((grant) => grant.config_id === config.id)?.supplicant_id ?? "";
  }

  assignWireGuardConfig(tunnel: WireGuardTunnel, config: WireGuardClientConfig, id: string) {
    if (id === this.wireGuardAssignee(tunnel, config)) return;
    if (id && (!this.isMember(id) || this.hasGrant(tunnel, id))) return;
    tunnel.grants = tunnel.grants.filter((grant) => grant.config_id !== config.id);
    if (id) {
      tunnel.grants.push({ supplicant_id: id, config_id: config.id });
    }
  }

  removeWireGuardConfig(tunnel: WireGuardTunnel, config: WireGuardClientConfig) {
    tunnel.configs = tunnel.configs.filter((item) => item !== config);
    tunnel.grants = tunnel.grants.filter((grant) => grant.config_id !== config.id);
    this.pendingRemoval.set(null);
  }

  addPeer(config: WireGuardClientConfig) {
    config.peers.push({
      server: "",
      port: 51820,
      public_key: "",
      allowed_ips: [],
      has_pre_shared_key: false,
    });
  }

  isPending(removal: Partial<PendingRemoval> & { kind: PendingRemoval["kind"] }) {
    const pending = this.pendingRemoval();
    if (!pending || pending.kind !== removal.kind) return false;
    return Object.entries(removal).every(
      ([key, value]) => pending[key as keyof PendingRemoval] === value,
    );
  }

  // WireGuard import

  toggleImport(target: ImportTarget) {
    this.importing.update((open) => (open === target ? null : target));
    this.importNotice.set(undefined);
  }

  importPortal(tunnel: Portal, config: string): boolean {
    const result = parseWireGuardImport(config);
    if (!result.ok) {
      this.importNotice.set({ target: tunnel, key: result.error });
      return false;
    }
    tunnel.server = result.server;
    tunnel.port = result.port;
    tunnel.subnet = result.suggestedSubnet || tunnel.subnet;
    tunnel.allowed_ips = result.routes;
    this.importNotice.set({ target: tunnel, key: result.server ? "reviewPortal" : "wildcard" });
    this.importing.set(null);
    return true;
  }

  importClient(config: WireGuardClientConfig, content: string): boolean {
    const result = parseWireGuardClient(content);
    if (!result.ok) {
      this.importNotice.set({ target: config, key: result.error });
      return false;
    }
    Object.assign(config, result.settings);
    this.importNotice.set({ target: config, key: "reviewClient" });
    this.importing.set(null);
    return true;
  }

  noticeFor(target: ImportTarget) {
    const notice = this.importNotice();
    if (notice?.target !== target) return undefined;
    return { key: notice.key, review: REVIEW_NOTICES.has(notice.key) };
  }

  // Routes

  recomputeRoutes() {
    this.recalculating.set(true);
    this.error.set(false);
    const routes = this.network.tunnels.flatMap((tunnel) => {
      if (tunnel.type === "wireguard-compatible") {
        return tunnel.configs.flatMap((config) => config.peers.flatMap((peer) => peer.allowed_ips));
      }
      const subnet = tunnel.subnet.trim();
      return subnet ? [...tunnel.allowed_ips, subnet] : tunnel.allowed_ips;
    });
    this.service
      .aggregateVlanRoutes(routes)
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.recalculating.set(false)),
      )
      .subscribe({
        next: (routes) => {
          this.network.routes = routes;
        },
        error: () => this.error.set(true),
      });
  }

  // Saving

  get incompleteWireGuard() {
    return this.network.tunnels.some(
      (tunnel) =>
        tunnel.type === "wireguard-compatible" &&
        tunnel.configs.some((config) => !config.addresses.length || !config.peers.length),
    );
  }

  /** The first reason saving is blocked, shown in the footer once the user tried to save. */
  blocker(form: NgForm): string | undefined {
    if (form.invalid) return "invalid";
    if (this.incompleteWireGuard) return "incompleteWireGuard";
    const { enabled, tunnels, routes } = this.network;
    if (enabled && (!tunnels.length || !routes.length)) return "enabledIncomplete";
    return undefined;
  }

  submit(form: NgForm) {
    this.attempted.set(true);
    if (this.blocker(form)) {
      form.control.markAllAsTouched();
      // Defer until touched styling renders so focus lands on a visibly invalid field.
      queueMicrotask(() =>
        this.host?.nativeElement
          .querySelector<HTMLElement>("input.ng-invalid, .ng-invalid input, textarea.ng-invalid")
          ?.focus(),
      );
      return;
    }
    this.save();
  }

  save() {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(false);
    this.service
      .saveVlan(structuredClone(this.network))
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: (network) => this.saved.emit(network),
        error: () => this.error.set(true),
      });
  }
}
