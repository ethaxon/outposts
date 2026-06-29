import { Directive } from "@angular/core";
import { BrnSheetDescription } from "@spartan-ng/brain/sheet";
import { classes } from "@/components/ui/utils";

@Directive({
  selector: "[hlmSheetDescription]",
  hostDirectives: [BrnSheetDescription],
  host: { "data-slot": "sheet-description" },
})
export class HlmSheetDescription {
  constructor() {
    classes(() => "text-muted-foreground text-sm");
  }
}
