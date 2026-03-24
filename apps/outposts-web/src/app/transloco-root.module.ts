import { NgModule } from "@angular/core";
import { provideTransloco, TranslocoModule } from "@jsverse/transloco";
import { TranslocoConfig } from "@/app/transloco-config";

@NgModule({
	exports: [TranslocoModule],
	providers: [provideTransloco(TranslocoConfig)],
})
export class TranslocoRootModule {}
