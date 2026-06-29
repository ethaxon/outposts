import { Directive } from "@angular/core";
import { HlmSeparator } from "@/components/ui/separator";
import { classes } from "@/components/ui/utils";

@Directive({
  selector: "[hlmSidebarSeparator],hlm-sidebar-separator",
  hostDirectives: [HlmSeparator],
  host: {
    "data-slot": "sidebar-separator",
    "data-sidebar": "separator",
  },
})
export class HlmSidebarSeparator {
  constructor() {
    classes(() => "bg-sidebar-border mx-2 w-auto");
  }
}
