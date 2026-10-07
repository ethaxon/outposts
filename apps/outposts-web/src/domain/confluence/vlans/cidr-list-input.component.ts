import {
  ChangeDetectionStrategy,
  Component,
  type ElementRef,
  forwardRef,
  input,
  signal,
  viewChild,
} from "@angular/core";
import {
  type ControlValueAccessor,
  NG_VALIDATORS,
  NG_VALUE_ACCESSOR,
  type ValidationErrors,
  type Validator,
} from "@angular/forms";
import { TranslocoModule } from "@jsverse/transloco";
import { NgIcon, provideIcons } from "@ng-icons/core";
import { lucideX } from "@ng-icons/lucide";
import { parseCidr, splitCidrTokens } from "./cidr";

type CidrNotice =
  | { kind: "invalid"; token: string }
  | { kind: "duplicate" | "normalized"; token: string; cidr: string };

const COMMIT_KEYS = new Set(["Enter", ",", ";", " "]);

/**
 * Tag-style editor for a list of IPv4/IPv6 CIDRs.
 *
 * Entries are validated and canonicalized as they are added, so the bound
 * `string[]` only ever holds values the backend accepts. Text that is still
 * being typed or failed to parse makes the control invalid, so a form cannot
 * be saved while silently dropping it.
 */
@Component({
  selector: "app-cidr-list-input",
  imports: [NgIcon, TranslocoModule],
  templateUrl: "./cidr-list-input.component.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
  providers: [
    {
      provide: NG_VALUE_ACCESSOR,
      useExisting: forwardRef(() => CidrListInputComponent),
      multi: true,
    },
    { provide: NG_VALIDATORS, useExisting: forwardRef(() => CidrListInputComponent), multi: true },
  ],
  viewProviders: [provideIcons({ lucideX })],
})
export class CidrListInputComponent implements ControlValueAccessor, Validator {
  readonly inputId = input<string>();
  readonly placeholder = input("");

  readonly values = signal<string[]>([]);
  readonly draft = signal("");
  readonly notice = signal<CidrNotice | undefined>(undefined);
  readonly disabled = signal(false);

  private readonly field = viewChild.required<ElementRef<HTMLInputElement>>("field");
  private onChange: (value: string[]) => void = () => {};
  private onTouched: () => void = () => {};
  private onValidatorChange: () => void = () => {};

  writeValue(value: string[] | null | undefined): void {
    this.values.set([...(value ?? [])]);
  }

  registerOnChange(fn: (value: string[]) => void): void {
    this.onChange = fn;
  }

  registerOnTouched(fn: () => void): void {
    this.onTouched = fn;
  }

  registerOnValidatorChange(fn: () => void): void {
    this.onValidatorChange = fn;
  }

  setDisabledState(disabled: boolean): void {
    this.disabled.set(disabled);
  }

  validate(): ValidationErrors | null {
    return this.draft().trim() ? { cidrPending: this.draft().trim() } : null;
  }

  onInput(text: string): void {
    this.draft.set(text);
    this.notice.set(undefined);
    this.onValidatorChange();
  }

  onKeydown(event: KeyboardEvent): void {
    if (COMMIT_KEYS.has(event.key) && this.draft().trim()) {
      // Also keeps Enter from submitting the surrounding form mid-entry.
      event.preventDefault();
      this.commit();
    } else if (event.key === "Backspace" && !this.draft() && this.values().length) {
      event.preventDefault();
      this.edit(this.values().length - 1);
    }
  }

  onPaste(event: ClipboardEvent): void {
    const text = event.clipboardData?.getData("text") ?? "";
    if (splitCidrTokens(text).length < 2) return;
    event.preventDefault();
    this.commit(`${this.draft()} ${text}`);
  }

  onBlur(): void {
    if (this.draft().trim()) this.commit();
    this.onTouched();
  }

  /** Adds every valid token; invalid ones stay in the input for correction. */
  commit(text = this.draft()): void {
    const values = [...this.values()];
    const rejected: string[] = [];
    let notice: CidrNotice | undefined;

    for (const token of splitCidrTokens(text)) {
      const parsed = parseCidr(token);
      if (!parsed.ok) {
        rejected.push(token);
        notice ??= { kind: "invalid", token };
      } else if (values.includes(parsed.cidr)) {
        notice ??= { kind: "duplicate", token, cidr: parsed.cidr };
      } else {
        values.push(parsed.cidr);
        if (parsed.adjusted) notice ??= { kind: "normalized", token, cidr: parsed.cidr };
      }
    }

    this.notice.set(notice);
    this.draft.set(rejected.join(" "));
    if (values.length !== this.values().length) {
      this.values.set(values);
      this.onChange(values);
    }
    this.onValidatorChange();
  }

  remove(index: number): void {
    const values = this.values().filter((_, i) => i !== index);
    this.values.set(values);
    this.onChange(values);
    this.onTouched();
    this.field().nativeElement.focus();
  }

  /** Moves an entry back into the input, keeping any text already being typed. */
  edit(index: number): void {
    if (this.draft().trim()) this.commit();
    const value = this.values()[index];
    if (value === undefined) return;
    this.remove(index);
    this.draft.set(this.draft() ? `${this.draft()} ${value}` : value);
    this.notice.set(undefined);
    this.onValidatorChange();
  }

  focus(): void {
    this.field().nativeElement.focus();
  }
}
