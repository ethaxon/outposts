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
  it("prefills the Portal without storing the exported client secret or changing VLAN routes", () => {
    const { component, service } = harness();
    component.addTunnel("easytier-gateway");
    const portal = component.network.tunnels[0];
    if (portal.type !== "easytier-gateway") throw new Error("Expected EasyTier tunnel");
    const pasted = [
      "[Interface]",
      "PrivateKey = example-client-key",
      "Address = 192.0.2.2/32",
      "[Peer]",
      "PublicKey = example-peer-key",
      "AllowedIPs = 10.20.0.0/24, 10.22.0.0/24",
      "Endpoint = portal.example.test:24",
      "PersistentKeepalive = 25",
    ].join("\n");
    expect(component.importPortal(portal, pasted)).toBe(true);
    expect(portal).toMatchObject({
      name: "",
      server: "portal.example.test",
      port: 24,
      subnet: "192.0.2.0/24",
      allowed_ips: ["10.20.0.0/24", "10.22.0.0/24"],
    });
    expect(portal.private_key).toBeUndefined();
    expect(component.network.routes).toEqual(["10.20.0.0/24", "10.21.0.0/24"]);
    expect(service.saveVlan).not.toHaveBeenCalled();
    expect(component.importPortal(portal, pasted.replace(":24", ":0"))).toBe(false);
    expect(portal.port).toBe(24);
  });

  it("replaces the route draft with the aggregated union of both tunnel types", () => {
    const { component, service } = harness();
    component.network.tunnels = [
      {
        id: "",
        name: "a",
        type: "easytier-gateway",
        server: "a.test",
        port: 24,
        subnet: "10.3.0.0/24",
        has_private_key: true,
        allowed_ips: ["10.20.0.0/24"],
        grants: [],
      },
      {
        id: "",
        name: "b",
        type: "wireguard-compatible",
        grants: [{ supplicant_id: "identity-id", config_id: "client-config" }],
        configs: [
          {
            id: "client-config",
            has_private_key: true,
            addresses: ["192.0.2.2/32"],
            mtu: null,
            persistent_keepalive: null,
            peers: [
              {
                server: "b.test",
                port: 51820,
                public_key: "key",
                has_pre_shared_key: false,
                allowed_ips: ["10.21.0.0/24"],
              },
            ],
          },
        ],
      },
    ];
    component.recomputeRoutes();
    expect(service.aggregateVlanRoutes).toHaveBeenCalledWith([
      "10.20.0.0/24",
      "10.3.0.0/24",
      "10.21.0.0/24",
    ]);
    expect(component.network.routes).toEqual(["10.0.0.0/8"]);
    expect(service.saveVlan).not.toHaveBeenCalled();
    expect(component.memberGrantCount("identity-id")).toBe(1);
    component.removeMember("identity-id");
    expect(component.network.accept_supplicants).toEqual([]);
    expect(component.network.tunnels[1].grants).toEqual([]);
    expect(component.network.tunnels[1]).toMatchObject({ configs: [{ id: "client-config" }] });
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

    component.addTunnel("easytier-gateway");
    const tunnel = component.network.tunnels[0];
    if (tunnel.type !== "easytier-gateway") throw new Error("Expected EasyTier tunnel");
    component.togglePortalGrant(tunnel, "identity-id");
    expect(component.hasGrant(tunnel, "identity-id")).toBe(true);

    component.toggleMember("identity-id");
    expect(component.isMember("identity-id")).toBe(true);
    expect(component.pendingRemoval()).toEqual({ kind: "member", id: "identity-id" });
  });

  it("imports and saves a WireGuard config without a member, then assigns it separately", () => {
    const { component, service } = harness();
    component.network.enabled = true;
    component.network.accept_supplicants = [];
    component.addTunnel("wireguard-compatible");
    const tunnel = component.network.tunnels[0];
    if (tunnel.type !== "wireguard-compatible") throw new Error("Expected WireGuard tunnel");
    component.addWireGuardConfig(tunnel);
    const config = tunnel.configs[0];
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
    expect(tunnel.grants).toEqual([]);

    component.assignWireGuardConfig(tunnel, config, "identity-id");
    expect(tunnel.grants).toEqual([]);
    component.toggleMember("identity-id");
    component.assignWireGuardConfig(tunnel, config, "identity-id");
    expect(tunnel.grants).toEqual([{ supplicant_id: "identity-id", config_id: config.id }]);
    component.assignWireGuardConfig(tunnel, config, "");
    expect(tunnel.grants).toEqual([]);
    expect(tunnel.configs).toEqual([config]);

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
