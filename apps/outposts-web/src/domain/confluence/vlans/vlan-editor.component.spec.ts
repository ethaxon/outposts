import { Injector, runInInjectionContext } from "@angular/core";
import type { NgForm } from "@angular/forms";
import { of, Subject } from "rxjs";
import { describe, expect, it, vi } from "vitest";
import type { VlanNetwork } from "../bindings/VlanNetwork";
import { ConfluenceService } from "../confluence.service";
import { VlanEditorComponent } from "./vlan-editor.component";

function harness() {
  const response = new Subject<VlanNetwork>();
  const service = {
    saveVlan: vi.fn((_network: VlanNetwork) => response),
    aggregateVlanRoutes: vi.fn((_routes: string[]) => of(["10.0.0.0/8"])),
  };
  const injector = Injector.create({
    providers: [{ provide: ConfluenceService, useValue: service }],
  });
  const component = runInInjectionContext(injector, () => new VlanEditorComponent());
  component.network.id = "network-id";
  component.network.network = "demo";
  component.network.accept_supplicants = [{ supplicant_id: "identity-id" }];
  component.network.routes = ["10.20.0.0/24", "10.21.0.0/24"];
  return { component, service, response };
}

describe("VLAN editor", () => {
  it("replaces the route draft with the aggregated AllowedIPs across tunnels", () => {
    const { component, service } = harness();
    for (const cidr of ["10.20.0.0/24", "10.21.0.0/24"]) {
      component.addTunnel();
      const { config } = component.network.tunnels.at(-1)!;
      component.addPeer(config);
      config.peers[0].allowed_ips = [cidr];
    }
    component.recomputeRoutes();
    expect(service.aggregateVlanRoutes).toHaveBeenCalledWith(["10.20.0.0/24", "10.21.0.0/24"]);
    expect(component.network.routes).toEqual(["10.0.0.0/8"]);
    expect(service.saveVlan).not.toHaveBeenCalled();
  });

  it("saves independently and prevents a duplicate update while pending", () => {
    const { component, service, response } = harness();
    component.save();
    component.save();
    expect(service.saveVlan).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        id: "network-id",
        accept_supplicants: [{ supplicant_id: "identity-id" }],
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

  it("toggles membership directly and confirms before dropping granted tunnels", () => {
    const { component } = harness();
    component.toggleMember("other-id");
    expect(component.isMember("other-id")).toBe(true);
    component.toggleMember("other-id");
    expect(component.isMember("other-id")).toBe(false);

    component.addTunnel();
    const tunnel = component.network.tunnels[0];
    component.toggleTunnelGrant(tunnel, "identity-id");
    expect(component.hasGrant(tunnel, "identity-id")).toBe(true);

    component.toggleMember("identity-id");
    expect(component.isMember("identity-id")).toBe(true);
    expect(component.pendingRemoval()).toEqual({ kind: "member", id: "identity-id" });
  });

  it("imports and saves a WireGuard config without a member, then grants the same tunnel to multiple VLAN members", () => {
    const { component, service } = harness();
    component.network.enabled = true;
    component.network.accept_supplicants = [];
    component.addTunnel();
    const tunnel = component.network.tunnels[0];
    const config = tunnel.config;
    const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const content = [
      "[Interface]",
      "PrivateKey = " + key,
      "Address = 192.0.2.2/32",
      "[Peer]",
      "PublicKey = " + key,
      "AllowedIPs = 10.20.0.0/24",
      "Endpoint = vpn.example.test:51820",
    ].join("\n");

    expect(component.importClient(config, content)).toBe(true);
    const form = { invalid: false } as NgForm;
    component.submit(form);
    expect(service.saveVlan).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ accept_supplicants: [], tunnels: [tunnel] }),
    );
    expect(tunnel.supplicant_ids).toEqual([]);

    component.toggleTunnelGrant(tunnel, "identity-id");
    expect(tunnel.supplicant_ids).toEqual([]);
    for (const member of ["identity-id", "second-id"]) {
      component.toggleMember(member);
      component.toggleTunnelGrant(tunnel, member);
    }
    expect(tunnel.supplicant_ids).toEqual(["identity-id", "second-id"]);
    component.removeMember("identity-id");
    expect(tunnel.supplicant_ids).toEqual(["second-id"]);
    expect(tunnel.config).toBe(config);

    component.requestRemoveTunnel(tunnel);
    expect(component.isPending({ kind: "tunnel", tunnel })).toBe(true);
    component.removeTunnel(tunnel);
    expect(component.network.tunnels).toEqual([]);
    expect(component.pendingRemoval()).toBeNull();
  });

  it("explains why saving is blocked instead of sending an invalid draft", () => {
    const { component, service } = harness();
    const markAllAsTouched = vi.fn();
    const form = (invalid: boolean) =>
      ({ invalid, control: { markAllAsTouched } }) as unknown as NgForm;

    component.network.enabled = true;
    expect(component.blocker(form(true))).toBe("invalid");
    expect(component.blocker(form(false))).toBe("enabledIncomplete");

    component.submit(form(false));
    expect(component.attempted()).toBe(true);
    expect(markAllAsTouched).toHaveBeenCalled();
    expect(service.saveVlan).not.toHaveBeenCalled();

    component.network.enabled = false;
    component.submit(form(false));
    expect(service.saveVlan).toHaveBeenCalledOnce();
  });
});
