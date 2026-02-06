import { CommonModule } from "@angular/common";
import { NgModule } from "@angular/core";
import { ClipboardService } from "./clipboard.service";

@NgModule({
	providers: [ClipboardService],
	declarations: [],
	exports: [],
	imports: [CommonModule],
})
export class ClipboardModule {}
