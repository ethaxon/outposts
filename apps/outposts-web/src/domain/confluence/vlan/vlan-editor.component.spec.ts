import { Injector, runInInjectionContext } from "@angular/core";
import { Subject } from "rxjs";
import { describe, expect, it, vi } from "vitest";
import type { VlanNetwork } from "../bindings/VlanNetwork";
import { ConfluenceService } from "../confluence.service";
import { VlanEditorComponent } from "./vlan-editor.component";

function harness() {
  const response = new Subject<VlanNetwork>();
  const service = { saveVlan: vi.fn((_network: VlanNetwork) => response) };
  const injector = Injector.create({
    providers: [{ provide: ConfluenceService, useValue: service }],
  });
  const component = runInInjectionContext(injector, () => new VlanEditorComponent());
  component.network.id = "network-id";
  component.network.network = "demo";
  component.network.accept_supplicants = [{ supplicant_id: "identity-id", slots: "2,4,10-100" }];
  component.network.routes = ["10.20.0.0/24", "10.21.0.0/24"];
  return { component, service, response };
}

describe("VLAN editor", () => {
  it("saves the VLAN independently with its supplicant references", () => {
    const { component, service, response } = harness();
    component.save();
    component.save();
    expect(service.saveVlan).toHaveBeenCalledTimes(1);
    expect(service.saveVlan).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "network-id",
        routes: ["10.20.0.0/24", "10.21.0.0/24"],
        accept_supplicants: [{ supplicant_id: "identity-id", slots: "2,4,10-100" }],
      }),
    );
    response.complete();
    expect(component.busy()).toBe(false);
  });

  it("retains the draft after a failed save", () => {
    const { component, response } = harness();
    component.save();
    response.error(new Error("failed"));
    expect(component.busy()).toBe(false);
    expect(component.error()).toBe(true);
    expect(component.network.network).toBe("demo");
  });
});
