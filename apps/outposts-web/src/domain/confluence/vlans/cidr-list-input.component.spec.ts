import { Injector, runInInjectionContext } from "@angular/core";
import { describe, expect, it, vi } from "vitest";
import { CidrListInputComponent } from "./cidr-list-input.component";

function harness(initial: string[] = []) {
  const component = runInInjectionContext(Injector.create({ providers: [] }), () => {
    return new CidrListInputComponent();
  });
  const onChange = vi.fn();
  component.registerOnChange(onChange);
  component.writeValue(initial);
  return { component, onChange };
}

// Tests run without a DOM, so a minimal stand-in replaces KeyboardEvent.
function key(key: string) {
  return { key, preventDefault: vi.fn() } as unknown as KeyboardEvent & {
    preventDefault: ReturnType<typeof vi.fn>;
  };
}

describe("CidrListInputComponent", () => {
  it("adds canonical entries and reports the new list", () => {
    const { component, onChange } = harness(["10.0.0.0/8"]);
    component.onInput("192.168.1.9/24");
    component.onKeydown(key("Enter"));

    expect(component.values()).toEqual(["10.0.0.0/8", "192.168.1.0/24"]);
    expect(onChange).toHaveBeenLastCalledWith(["10.0.0.0/8", "192.168.1.0/24"]);
    expect(component.notice()).toEqual({
      kind: "normalized",
      token: "192.168.1.9/24",
      cidr: "192.168.1.0/24",
    });
    expect(component.validate()).toBeNull();
  });

  it("keeps invalid tokens in the input and blocks the form", () => {
    const { component } = harness();
    component.commit("10.20.0.0/24 nope fd00::/64");

    expect(component.values()).toEqual(["10.20.0.0/24", "fd00::/64"]);
    expect(component.draft()).toBe("nope");
    expect(component.notice()).toEqual({ kind: "invalid", token: "nope" });
    expect(component.validate()).toEqual({ cidrPending: "nope" });
  });

  it("ignores duplicates after canonicalization", () => {
    const { component, onChange } = harness(["10.20.0.0/24"]);
    component.commit("10.20.0.5/24");

    expect(component.values()).toEqual(["10.20.0.0/24"]);
    expect(onChange).not.toHaveBeenCalled();
    expect(component.notice()?.kind).toBe("duplicate");
  });

  it("does not intercept Enter when nothing is being typed", () => {
    const { component } = harness();
    const enter = key("Enter");
    component.onKeydown(enter);
    expect(enter.preventDefault).not.toHaveBeenCalled();
  });

  it("treats uncommitted text as pending until it is added", () => {
    const { component } = harness();
    component.onInput("10.1.0.0/16");
    expect(component.validate()).toEqual({ cidrPending: "10.1.0.0/16" });
  });
});
