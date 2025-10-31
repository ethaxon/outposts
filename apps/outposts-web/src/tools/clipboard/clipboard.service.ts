
import { Injectable, inject, DOCUMENT } from "@angular/core";
import { WINDOW } from '@/core/providers/window';

@Injectable()
export class ClipboardService {
  protected readonly window = inject(WINDOW);
  protected readonly document = inject(DOCUMENT);
  protected readonly navigator = this.window.navigator;
  protected readonly ClipboardJS = this.window.ClipboardJS;

  async copyText(text: string) {
    await this.navigator.clipboard.writeText(text);
  }

  async copyEl(target: string | Element) {
    this.ClipboardJS.copy(target)
  }
}