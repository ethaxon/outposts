import type { AbstractControl, ValidationErrors } from "@angular/forms";
import { parse as parseCron } from "@datasert/cronjs-parser";

export function hourPlusLevelCronExprValidator(
  control: AbstractControl<string>,
): ValidationErrors | null {
  const value = control.value;
  if (!value) {
    return { emptyCronExpr: true };
  }
  try {
    const parsedExpr = parseCron(value);
    return parsedExpr.expressions.some((expr) => {
      if (!expr.second.omit) {
        return true;
      }
      const keys = Object.keys(expr.minute);
      if (keys.length !== 1 || keys[0] !== "values") {
        return true;
      }
      return false;
    })
      ? {
          invalidCronExprSupportLevel: true,
          messageKey: "confluence.workspace.validation.cron.hourlyMinimum",
        }
      : null;
  } catch (e: unknown) {
    return {
      parseCronExprError: e,
      messageKey: "confluence.workspace.validation.cron.invalidFormat",
    };
  }
}
