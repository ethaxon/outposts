import { inject, Injectable, DestroyRef, NgZone, EnvironmentInjector, signal, afterNextRender, DOCUMENT } from "@angular/core";
import { DocTableOfContentsLoader } from '@/tools/doc/services/doc-table-of-contents-loader.service';
import { ViewportScroller } from "@angular/common";
import { WINDOW } from '@/core/providers/window';
import {
  auditTime,
  debounceTime,
  filter,
  fromEvent,
  fromEventPattern,
  map,
  startWith,
  tap
} from "rxjs";
import { RESIZE_EVENT_DELAY, SCROLL_EVENT_DELAY } from '@/core/defs/delay';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { shouldReduceMotion } from '@/tools/animation.utils';
import { Router, Scroll } from "@angular/router";
import { clamp } from "es-toolkit";

@Injectable()
export class DocTableOfContentsSpy {
  private readonly destroyRef = inject(DestroyRef);
  private readonly tableOfContentsLoader = inject(DocTableOfContentsLoader);
  private readonly document = inject(DOCUMENT);
  private readonly window = inject(WINDOW);
  private readonly ngZone = inject(NgZone);
  private readonly viewportScroller = inject(ViewportScroller);
  private readonly injector = inject(EnvironmentInjector);
  private readonly router = inject(Router);
  private contentSourceElement: HTMLElement | null = null;
  private tocElement: HTMLElement | null = null;
  private lastContentWidth = 0;

  activeItemId = signal<string | null>(null);
  scrollbarThumbOnTop = signal(true);

  startListeningChange(contentSourceElement: HTMLElement | null, tocElement: HTMLElement): void {
    this.contentSourceElement = contentSourceElement;
    this.lastContentWidth = this.getContentWidth();
    this.tocElement = tocElement;

    this.setAnchorScrollingHandlers();
    this.setMutationEventHandlers();
    this.setScrollEventHandlers();
    this.setResizeEventHandlers();
  }

  private getTocTop() {
    return clamp(this.tocElement?.getBoundingClientRect?.().top ?? 0, 0, this.document.body.clientHeight);
  }

  scrollToTop(): void {
    this.viewportScroller.scrollToPosition([0, 0]);
  }

  scrollToSection(id: string): void {
    if (shouldReduceMotion()) {
      this.offsetToSection(id, 'instant');
    } else {
      this.offsetToSection(id, 'smooth')
    }
  }

  private offsetToSection(id: string, preferBehavior: 'instant' | 'smooth' = 'instant'): void {
    const body = this.document.body;
    const section = this.document.getElementById(id);
    if (body && section) {
      const bodyTop = body.getBoundingClientRect().top;
      const sectionTop = section.getBoundingClientRect().top;
      const sectionScrollY = sectionTop - bodyTop - this.getTocTop();
      const prevX = this.viewportScroller.getScrollPosition()[0];
      const realBehavior = preferBehavior === 'smooth' && 'scrollBehavior' in this.document.documentElement.style ? 'smooth' : 'instant';

      if (realBehavior === 'instant') {
        this.document.body.scrollTop = sectionScrollY;
        if (this.document.documentElement) {
          this.document.documentElement.scrollTop = sectionScrollY;
        }
      } else {
        this.window.scrollTo({
          left: prevX,
          top: sectionScrollY,
          behavior: 'smooth'
        });
      }

      if (realBehavior === 'instant') {
        // Here we need to set the active item manually because scroll events might not be fired
        this.activeItemId.set(id);
      }
    }
  }

  private setAnchorScrollingHandlers() {
    this.router.events
      .pipe(
        filter((e): e is Scroll => e instanceof Scroll),
        tap((e) => {
          const id = e.anchor;
          if (id && this.tableOfContentsLoader.tableOfContentsItems.some(item => item.id === id)) {
            this.scrollToSection(id);
          }
        }),
        takeUntilDestroyed(this.destroyRef),
      ).subscribe()
  }

  private setMutationEventHandlers() {
    const docsViewer = this.contentSourceElement;
    if (docsViewer) {
      afterNextRender(() => {
        fromEventPattern<[MutationRecord[]]>(handler => {
          const observer = new MutationObserver(handler);
          observer.observe(docsViewer, {
            subtree: true,
            childList: true,
            attributeFilter: ['id']
          })
          return observer;
        }, (_, observer) => {
          observer.disconnect();
        }).pipe(
          map(([mutations]) => mutations.filter((m) => {
            switch (m.type) {
              case 'attributes':
                if (m.attributeName === 'id' && this.tableOfContentsLoader.isHeading(m?.target)) {
                  return true;
                }
                break;
              case 'childList':
                if (this.tableOfContentsLoader.isHeading(m?.target)) {
                  return true;
                }
                if (Array.from(m.addedNodes).some(n => this.tableOfContentsLoader.isHeading(n))) {
                  return true;
                }
                if (Array.from(m.addedNodes).some(n => this.tableOfContentsLoader.isHeading(n))) {
                  return true;
                }
                break;
              default:
            }
            return false;
          }
          )
          ),
          filter(mutations => mutations.length > 0),
          takeUntilDestroyed(this.destroyRef)
        ).subscribe(
          (_mutations) => {
            this.tableOfContentsLoader.buildTableOfContents(docsViewer)
          }
        )
      }, {
        injector: this.injector
      });
    }
  }

  private setResizeEventHandlers() {
    fromEvent(this.window, 'resize')
      .pipe(
        debounceTime(RESIZE_EVENT_DELAY),
        takeUntilDestroyed(this.destroyRef),
        startWith(undefined),
      ).subscribe(() => {
        this.ngZone.run(() => this.updateHeadingsTopAfterResize());
      });

    const docsViewer = this.contentSourceElement;
    if (docsViewer) {
      afterNextRender(() => {
        const resizeObserver = new ResizeObserver(() => this.updateHeadingsTopAfterResize());
        resizeObserver.observe(docsViewer);
        this.destroyRef.onDestroy(() => resizeObserver.disconnect());
      }, {
        injector: this.injector
      });
    }
  }

  private updateHeadingsTopAfterResize() {
    this.lastContentWidth = this.getContentWidth();
    const contentElement = this.contentSourceElement;
    if (contentElement) {
      this.tableOfContentsLoader.updateHeadingsTopValue(contentElement);
      this.setActiveItemId();
    }
  }

  private setScrollEventHandlers() {
    const scroll$ = fromEvent(this.document, 'scroll')
      .pipe(
        auditTime(SCROLL_EVENT_DELAY),
        takeUntilDestroyed(this.destroyRef)
      );

    this.ngZone.runOutsideAngular(() => {
      scroll$.subscribe(this.setActiveItemId.bind(this))
    })
  }

  private setActiveItemId() {
    const tableOfContentItems = this.tableOfContentsLoader.tableOfContentsItems;

    if (tableOfContentItems.length === 0) {
      return;
    }

    if (this.lastContentWidth !== this.getContentWidth()) {
      return;
    }

    const scrollOffset = this.getScrollOffset();

    if (scrollOffset === null) {
      return;
    }

    for (const [i, currentLink] of tableOfContentItems.entries()) {
      const nextLink = tableOfContentItems[i + 1];

      const isActive = scrollOffset >= currentLink.top && (!nextLink || nextLink.top > scrollOffset);

      if (isActive && this.activeItemId() !== currentLink.id) {
        this.ngZone.run(() => this.activeItemId.set(currentLink.id));
        return;
      }
    }

    if (scrollOffset < tableOfContentItems[0].top && this.activeItemId() !== null) {
      this.ngZone.run(() => this.activeItemId.set(null));
    }

    const scrollOffsetZero = scrollOffset === 0;
    if (scrollOffsetZero !== this.scrollbarThumbOnTop()) {
      this.ngZone.run(() => this.scrollbarThumbOnTop.set(scrollOffsetZero));
    }
  }

  private getScrollOffset() {
    return this.window.scrollY + this.getTocTop();
  }

  private getContentWidth(): number {
    return this.document.body.clientWidth || Number.MAX_SAFE_INTEGER;
  }
}
