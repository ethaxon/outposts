import { Directive, forwardRef, Injector, inject } from "@angular/core";
import {
  type AbstractControl,
  NG_VALIDATORS,
  NgControl,
  type ValidationErrors,
  type Validator,
} from "@angular/forms";

/**
 * Mirrors the backend `valid_name`: 1–64 RFC 3986 unreserved characters, lowercase.
 * Names are written unescaped into the subscription UA/URL, so separators such as
 * `, : & =` and whitespace can never be part of a name.
 */
export const VLAN_NAME = /^[a-z0-9._~-]{1,64}$/;

/**
 * Validates VLAN identifiers (network, gateway, supplicant names) and lowercases
 * input as it is typed, since uppercase is the most common reason a name is rejected.
 */
@Directive({
  selector: "input[appVlanName]",
  providers: [
    { provide: NG_VALIDATORS, useExisting: forwardRef(() => VlanNameDirective), multi: true },
  ],
  host: {
    autocapitalize: "off",
    autocomplete: "off",
    spellcheck: "false",
    maxlength: "64",
    "(input)": "lowercase($event)",
  },
})
export class VlanNameDirective implements Validator {
  // Resolved lazily: NgModel injects this validator, so eager NgControl injection is cyclic.
  private readonly injector = inject(Injector);

  validate(control: AbstractControl<string | null>): ValidationErrors | null {
    const value = control.value;
    return !value || VLAN_NAME.test(value) ? null : { vlanName: true };
  }

  lowercase(event: Event): void {
    const field = event.target as HTMLInputElement;
    // Rewriting mid-composition would break IME input; the final input event follows.
    if ((event as InputEvent).isComposing) return;
    const lower = field.value.toLowerCase();
    if (lower === field.value) return;

    const { selectionStart, selectionEnd } = field;
    this.injector.get(NgControl, null)?.control?.setValue(lower);
    field.value = lower;
    field.setSelectionRange(selectionStart, selectionEnd);
  }
}
