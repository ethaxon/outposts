import { Injectable, inject } from "@angular/core";
import { combineLatest, forkJoin, map, type Observable } from "rxjs";
import { AppAssetService } from "@/core/servces/app-asset.service";

@Injectable()
export class DocService {
	private readonly assetService = inject(AppAssetService);

	loadMermaid(): Observable<void> {
		return this.assetService.loadScript("mermaid.js") as Observable<any>;
	}

	isMermaidLoaded$(): Observable<boolean> {
		return this.assetService.isScriptLoaded$("mermaid.js");
	}

	loadKatex(): Observable<void> {
		return forkJoin([
			this.assetService.loadScript("katex.js"),
			this.assetService.loadLink("katex.css", { rel: "stylesheet" }),
		]) as Observable<any>;
	}

	isKatexLoaded$(): Observable<boolean> {
		return combineLatest([
			this.assetService.isScriptLoaded$("katex.js"),
			this.assetService.isLinkLoaded$("katex.css"),
		]).pipe(map(([scriptLoaded, styleLoaded]) => scriptLoaded && styleLoaded));
	}

	loadMarkdown(url: string): Observable<string> {
		return this.assetService.loadPlainText(url);
	}
}
