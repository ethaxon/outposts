import { FormControl } from "@angular/forms";
import { describe, expect, it } from "vitest";
import { hourPlusLevelCronExprValidator } from "../cron-expr.validators";

describe("hourPlusLevelCronExprValidator", () => {
  it("keeps the empty value as a structural validation error", () => {
    expect(hourPlusLevelCronExprValidator(new FormControl("", { nonNullable: true }))).toEqual({
      emptyCronExpr: true,
    });
  });

  it("returns a translation key rather than a parser error message", () => {
    expect(
      hourPlusLevelCronExprValidator(
        new FormControl("not a cron expression", { nonNullable: true }),
      ),
    ).toMatchObject({
      parseCronExprError: expect.anything(),
      messageKey: "confluence.workspace.validation.cron.invalidFormat",
    });
  });
});
