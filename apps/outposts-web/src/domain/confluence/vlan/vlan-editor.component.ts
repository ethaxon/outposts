import { Component, DestroyRef, inject, input, output, signal, type OnInit } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormsModule } from "@angular/forms";
import { TranslocoModule } from "@jsverse/transloco";
import { finalize } from "rxjs";
import { HlmButton } from "@/components/ui/button";
import { HlmInputImports } from "@/components/ui/input";
import type { VlanNetwork } from "../bindings/VlanNetwork";
import type { VlanSupplicant } from "../bindings/VlanSupplicant";
import { ConfluenceService } from "../confluence.service";
import { CidrListInputComponent } from "./cidr-list-input.component";
import { CidrDirective } from "./cidr.directive";

@Component({
  selector: "app-vlan-editor",
  imports: [
    FormsModule,
    TranslocoModule,
    HlmButton,
    ...HlmInputImports,
    CidrListInputComponent,
    CidrDirective,
  ],
  templateUrl: "./vlan-editor.component.html",
})
export class VlanEditorComponent implements OnInit {
  private readonly destroyRef = inject(DestroyRef);
  private readonly service = inject(ConfluenceService);
  readonly initial = input<VlanNetwork>();
  readonly identities = input.required<VlanSupplicant[]>();
  readonly saved = output<VlanNetwork>();
  readonly busy = signal(false);
  readonly error = signal(false);

  network: VlanNetwork = {
    id: "",
    enabled: false,
    network: "",
    routes: [],
    gateways: [],
    accept_supplicants: [],
  };
  get supplicants() {
    return this.identities();
  }

  ngOnInit() {
    const initial = this.initial();
    if (initial) this.network = structuredClone(initial);
  }

  addGateway() {
    this.network.gateways.push({
      name: "",
      server: "",
      port: 24,
      subnet: "",
      has_private_key: false,
    });
  }

  addGrant() {
    const available = this.identities().find(
      (item) => !this.network.accept_supplicants.some((grant) => grant.supplicant_id === item.id),
    );
    if (available)
      this.network.accept_supplicants.push({ supplicant_id: available.id, slots: "2-254" });
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
