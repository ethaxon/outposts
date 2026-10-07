import { Injector, runInInjectionContext } from "@angular/core";
import type { Observable } from "rxjs";
import { Subject } from "rxjs";
import { describe, expect, it, vi } from "vitest";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import type { VlanConfig } from "../bindings/VlanConfig";
import { ConfluenceService } from "../confluence.service";
import { VlanCatalogComponent } from "./vlan-catalog.component";

function harness() {
  // A fresh response per request, so a retry does not replay the previous failure.
  const responses: Subject<VlanConfig>[] = [];
  const service = {
    getVlanCatalog: vi.fn(() => {
      const response = new Subject<VlanConfig>();
      responses.push(response);
      return response;
    }),
  };
  const overlay = { withSuspense: vi.fn(<T>(source: Observable<T>) => source) };
  const injector = Injector.create({
    providers: [
      { provide: ConfluenceService, useValue: service },
      { provide: AppOverlayService, useValue: overlay },
    ],
  });
  const component = runInInjectionContext(injector, () => new VlanCatalogComponent());
  return { component, service, overlay, responses };
}

const catalog: VlanConfig = {
  vlan_configs: [
    { id: "b", enabled: true, network: "office", routes: [], tunnels: [], accept_supplicants: [] },
    { id: "a", enabled: false, network: "home", routes: [], tunnels: [], accept_supplicants: [] },
  ],
  supplicant_configs: [],
};

describe("VlanCatalogComponent loading", () => {
  it("loads through the app-wide suspense on its own page and renders sorted cards", () => {
    const { component, overlay, responses } = harness();
    component.ngOnInit();
    const [response] = responses;

    expect(overlay.withSuspense).toHaveBeenCalledOnce();
    expect(component.catalog()).toBeUndefined();
    expect(component.action()).toBe("refresh");

    response.next(catalog);
    response.complete();

    expect(component.action()).toBeUndefined();
    expect(component.networks().map((network) => network.network)).toEqual(["home", "office"]);
  });

  it("ends in the retryable error state when the first load fails", () => {
    const { component, service, responses } = harness();
    component.ngOnInit();
    responses[0].error(new Error("offline"));

    expect(component.catalog()).toBeUndefined();
    expect(component.error()).toBe("loadError");
    expect(component.busy()).toBe(false);

    component.refresh();
    expect(service.getVlanCatalog).toHaveBeenCalledTimes(2);
    expect(component.error()).toBe("");
    expect(component.action()).toBe("refresh");
  });
});
