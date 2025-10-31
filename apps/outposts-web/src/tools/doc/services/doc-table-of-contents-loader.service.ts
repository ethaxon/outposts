/**
 * some code fragments from [angular/dev-infra](https://github.com/angular/dev-infra/)
 */
import { inject, Injectable, PLATFORM_ID, DOCUMENT } from "@angular/core";
import { DocTableOfContentsItem, DocTableOfContentsLevel } from '@/tools/doc/defs/doc-table-of-contents.defs';
import { isPlatformBrowser } from "@angular/common";
import { WINDOW } from '@/core/providers/window';

@Injectable()
export class DocTableOfContentsLoader {
  // There are some cases when default browser anchor scrolls a little above the
  // heading In that cases wrong item was selected. The value found by trial and
  // error.
  readonly toleranceThreshold = 5;

  tableOfContentsItems: DocTableOfContentsItem[] = [];

  private readonly document = inject(DOCUMENT);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly window = inject(WINDOW);

  buildTableOfContents(docElement: Element): void {
    const headings = this.getHeadings(docElement);
    const tocList = headings.map((heading) => {
      return ({
        id: heading.id,
        level: heading.tagName.toLowerCase() as DocTableOfContentsLevel,
        title: this.getHeadingTitle(heading),
        top: this.calculateTop(heading)
      }) as DocTableOfContentsItem
    })

    this.tableOfContentsItems = tocList;
  }

  // Update top value of heading, it should be executed after window resize
  updateHeadingsTopValue(elememt: HTMLElement): void {
    const headings = this.getHeadings(elememt);
    const updatedTopValues = new Map<string, number>();

    for (const heading of headings) {
      const top = Math.floor(heading.getBoundingClientRect().top + this.window.scrollY - this.toleranceThreshold);
      updatedTopValues.set(heading.id, top);
    }

    this.tableOfContentsItems.forEach(item => {
      item.top = updatedTopValues.get(item.id) ?? 0;
    })
  }

  private calculateTop(heading: HTMLHeadingElement): number {
    if (!isPlatformBrowser(this.platformId)) {
      return 0;
    }
    return Math.floor(heading.getBoundingClientRect().top + this.window.scrollY - this.toleranceThreshold)
  }

  private getHeadingTitle(heading: HTMLHeadingElement): string {
    const div = this.document.createElement('div');
    div.innerHTML = heading.innerHTML;
    return (div.textContent || '').trim();
  }

  isHeading(element?: Node): boolean {
    return !!element && /^h[123456]$/i.test(element?.nodeName)
  }

  private getHeadings(element: Element): HTMLHeadingElement[] {
    return Array.from(
      element.querySelectorAll<HTMLHeadingElement>(
        [
          'h1[id]',
          'h2[id]',
          'h3[id]',
          'h4[id]',
          'h5[id]',
          'h6[id]'
        ].join(',')
      )
    )
  }
}
