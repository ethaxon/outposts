import { CommonModule, isPlatformBrowser } from "@angular/common";
import { HttpClient } from "@angular/common/http";
import { inject, NgModule, PLATFORM_ID, SecurityContext } from "@angular/core";
import { RouterLink } from "@angular/router";
import { gfmHeadingId } from "marked-gfm-heading-id";
import {
	MARKED_EXTENSIONS,
	MARKED_OPTIONS,
	MarkdownModule,
} from "ngx-markdown";
import { ButtonModule } from "primeng/button";
import { MessageModule } from "primeng/message";
import { SkeletonModule } from "primeng/skeleton";
import { StyleClassModule } from "primeng/styleclass";
import { WINDOW } from "@/core/providers/window";
import { DocClipboardButtonComponent } from "@/tools/doc/components/clipboard-button/doc-clipboard-button.component";
import { DocLayoutComponent } from "@/tools/doc/components/layout/doc-layout.component";
import { DocSectionComponent } from "@/tools/doc/components/section/doc-section.component";
import { DocTableOfContentsComponent } from "@/tools/doc/components/table-of-contents/doc-table-of-contents.component";
import { DocTableOfContentsLoader } from "@/tools/doc/services/doc-table-of-contents-loader.service";
import { DocTableOfContentsSpy } from "@/tools/doc/services/doc-table-of-contents-spy.service";
import { DocService } from "./services/doc.service";

@NgModule({
	providers: [DocService, DocTableOfContentsLoader, DocTableOfContentsSpy],
	declarations: [
		DocSectionComponent,
		DocClipboardButtonComponent,
		DocTableOfContentsComponent,
		DocLayoutComponent,
	],
	exports: [
		DocSectionComponent,
		DocClipboardButtonComponent,
		DocTableOfContentsComponent,
		DocLayoutComponent,
	],
	imports: [
		CommonModule,
		SkeletonModule,
		StyleClassModule,
		ButtonModule,
		MessageModule,
		RouterLink,
		MarkdownModule.forRoot({
			loader: HttpClient,
			sanitize: SecurityContext.NONE,
			markedExtensions: [
				{
					provide: MARKED_EXTENSIONS,
					useFactory: gfmHeadingId,
					multi: true,
				},
			],
			markedOptions: {
				provide: MARKED_OPTIONS,
				useValue: {
					gfm: true,
				},
			},
		}),
	],
})
export class DocModule {
	private readonly platformId = inject(PLATFORM_ID);
	private readonly window: Window = inject(WINDOW);

	constructor() {
		if (isPlatformBrowser(this.platformId) && this?.window?.Prism?.plugins) {
			const PrismPlugins = this?.window.Prism.plugins;
			if (PrismPlugins["autoloader"]) {
				PrismPlugins["autoloader"].languages_path =
					"/assets/prismjs/components/";
			}
		}
	}
}
