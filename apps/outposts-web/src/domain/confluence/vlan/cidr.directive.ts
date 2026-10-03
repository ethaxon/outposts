import { Directive, forwardRef, Injector, inject, input } from "@angular/core";
import {
  type AbstractControl,
  NG_VALIDATORS,
  NgControl,
  type ValidationErrors,
  type Validator,
} from "@angular/forms";
import { type IpFamily, parseCidr } from "./cidr";

/**
 * Validates a single CIDR text input and rewrites it to canonical form on blur
 * (e.g. `10.30.0.5/24` → `10.30.0.0/24`), matching what the backend requires.
 */
@Directive({
  selector: "input[appCidr]",
  providers: [
    { provide: NG_VALIDATORS, useExisting: forwardRef(() => CidrDirective), multi: true },
  ],
  host: { "(blur)": "normalize()" },
})
export class CidrDirective implements Validator {
  readonly cidrFamily = input<IpFamily>();
  readonly cidrPrefix = input<number>();
  // Resolved lazily: NgModel injects this validator, so eager NgControl injection is cyclic.
  private readonly injector = inject(Injector);

  validate(control: AbstractControl<string | null>): ValidationErrors | null {
    const value = control.value?.trim();
    if (!value) return null;
    const parsed = parseCidr(value, this.constraints());
    return parsed.ok ? null : { cidr: parsed.reason };
  }

  normalize(): void {
    const control = this.injector.get(NgControl, null)?.control;
    const value = control?.value;
    if (!control || typeof value !== "string" || !value.trim()) return;
    const parsed = parseCidr(value, this.constraints());
    if (parsed.ok && parsed.cidr !== value) control.setValue(parsed.cidr);
  }

  private constraints() {
    return { family: this.cidrFamily(), prefix: this.cidrPrefix() };
  }
}
