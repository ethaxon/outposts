import { Injector, runInInjectionContext } from "@angular/core";
import { FormControl, NgControl } from "@angular/forms";
import { describe, expect, it, vi } from "vitest";
import { VLAN_NAME, VlanNameDirective } from "./vlan-name.directive";

function harness(control = new FormControl<string | null>("")) {
  const injector = Injector.create({
    providers: [{ provide: NgControl, useValue: { control } }],
  });
  const directive = runInInjectionContext(injector, () => new VlanNameDirective());
  return { directive, control };
}

// Tests run without a DOM, so a minimal stand-in replaces the input element.
function typed(value: string, caret: number, isComposing = false) {
  const field = {
    value,
    selectionStart: caret,
    selectionEnd: caret,
    setSelectionRange: vi.fn(),
  };
  return { field, event: { target: field, isComposing } as unknown as Event };
}

describe("VLAN name rule", () => {
  it.each(["home", "home-lan", "home_lan", "home.lan", "~edge", "a".repeat(64)])(
    "accepts %j",
    (name) => expect(VLAN_NAME.test(name)).toBe(true),
  );

  it.each(["", "Home", "home lan", "home,lan", "home:lan", "home&lan", "家", "a".repeat(65)])(
    "rejects %j",
    (name) => expect(VLAN_NAME.test(name)).toBe(false),
  );
});

describe("VlanNameDirective", () => {
  it("leaves empty values to the required validator", () => {
    const { directive } = harness();
    expect(directive.validate(new FormControl(""))).toBeNull();
    expect(directive.validate(new FormControl("home:lan"))).toEqual({ vlanName: true });
  });

  it("lowercases typed input and keeps the caret in place", () => {
    const { directive, control } = harness();
    const { field, event } = typed("Home-LAN", 3);

    directive.lowercase(event);

    expect(field.value).toBe("home-lan");
    expect(control.value).toBe("home-lan");
    expect(field.setSelectionRange).toHaveBeenCalledWith(3, 3);
  });

  it("does not rewrite input while an IME composition is active", () => {
    const { directive, control } = harness();
    const { field, event } = typed("Home", 4, true);

    directive.lowercase(event);

    expect(field.value).toBe("Home");
    expect(control.value).toBe("");
  });
});
