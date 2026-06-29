import {
  Component,
  DestroyRef,
  Input,
  inject,
  type OnInit,
  ChangeDetectionStrategy,
} from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { isNil } from "es-toolkit";
import {
  combineLatest,
  distinctUntilChanged,
  EMPTY,
  filter,
  map,
  type Observable,
  of,
  shareReplay,
  startWith,
  switchMap,
  throwError,
} from "rxjs";
import { DocClipboardButtonComponent } from "@/tools/doc/components/clipboard-button/doc-clipboard-button.component";
import { Observe } from "@/tools/rx";
import { DocService } from "../../services/doc.service";

@Component({
  standalone: false,
  selector: "app-doc-section",
  templateUrl: "./doc-section.component.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: [
    "./doc-section.component.scss",
    // only works on direct child
    "../../styles/markdown-themes/github-markdown-light.css",
  ],
})
export class DocSectionComponent implements OnInit {
  private readonly docService = inject(DocService);
  private readonly destroyRef = inject(DestroyRef);

  readonly ClipboardButtonComponent = DocClipboardButtonComponent;

  @Input()
  skeleton = true;

  @Input()
  lineNumbers = false;

  @Input("data")
  propData?: string;

  @Input("src")
  propSrc?: string;

  @Observe("propData")
  propData$!: Observable<string | undefined>;

  @Observe("propSrc")
  propSrc$!: Observable<string | undefined>;

  propSrcData$: Observable<string | undefined> = this.propSrc$.pipe(
    distinctUntilChanged(),
    switchMap((src) => {
      if (src) {
        return this.docService.loadMarkdown(src).pipe(startWith(undefined));
      } else {
        return of("");
      }
    }),
    shareReplay(1),
  );

  data$ = combineLatest([
    this.propData$,
    this.propSrcData$.pipe(filter((data) => !isNil(data))) as Observable<string>,
  ]).pipe(
    map(([data, srcData]) => this.normalizeKatexSyntax(data ?? srcData)),
    shareReplay(1),
  );

  isDataReady$: Observable<boolean> = combineLatest([
    this.propData$.pipe(map(() => true)),
    this.propSrc$.pipe(map((data) => !isNil(data))),
  ]).pipe(map(([dataReady, srcReady]) => dataReady || srcReady));

  isPrismLoaded$: Observable<boolean> = this.docService.isPrismLoaded$();

  isMermaidRequired$: Observable<boolean> = this.data$.pipe(map(this.detectMermaid.bind(this)));
  isMermaidLoaded$: Observable<boolean> = this.docService.isMermaidLoaded$();

  isKatexRequired$: Observable<boolean> = this.data$.pipe(map(this.detectKatex.bind(this)));
  isKatexLoaded$: Observable<boolean> = this.docService.isKatexLoaded$();

  isResourceReady$: Observable<boolean> = combineLatest([
    this.isPrismLoaded$,
    this.isMermaidRequired$,
    this.isMermaidLoaded$,
    this.isKatexRequired$,
    this.isKatexLoaded$,
    this.data$,
  ]).pipe(
    map(
      ([prismLoaded, mermaidRequired, mermaidLoaded, katexRequired, katexLoaded]) =>
        prismLoaded && (!mermaidRequired || mermaidLoaded) && (!katexRequired || katexLoaded),
    ),
  );

  private normalizeKatexSyntax(data: string): string {
    return data.replace(/\\\r?\n/g, "\\\\\n");
  }

  detectMermaid(data: string) {
    return /```mermaid/.test(data);
  }

  detectKatex(data: string) {
    return /\$\$[^$]+?\$\$|\$[^\n\r$]+?\$|katex/.test(data);
  }

  ngOnInit(): void {
    this.docService.loadPrism().pipe(takeUntilDestroyed(this.destroyRef)).subscribe();
    this.isMermaidRequired$
      .pipe(
        filter((hasMermaid) => hasMermaid),
        switchMap(() => this.docService.loadMermaid()),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe();
    this.isKatexRequired$
      .pipe(
        filter((hasKatex) => hasKatex),
        switchMap(() => this.docService.loadKatex()),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe();
    combineLatest([this.propData$, this.propSrc$])
      .pipe(
        switchMap(([data, src]) => {
          if (isNil(data) && isNil(src)) {
            return throwError(
              () => new Error("DocSectionComponent Error: can not set both src and data"),
            );
          }
          return EMPTY;
        }),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe();
  }
}
