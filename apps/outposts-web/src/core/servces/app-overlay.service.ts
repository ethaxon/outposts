import { DestroyRef, Injectable, inject } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { TranslocoService } from "@jsverse/transloco";
import { MessageService, type ToastMessageOptions } from "primeng/api";
import { BehaviorSubject, type Observable, Subject } from "rxjs";
import { withSuspense } from "@/tools/rx";

@Injectable()
export class AppOverlayService {
  protected readonly destoryRef = inject(DestroyRef);
  protected readonly messageService = inject(MessageService);
  protected readonly translocoService = inject(TranslocoService);
  readonly error$$ = new Subject<any>();
  readonly loading$$ = new BehaviorSubject<boolean>(false);

  constructor() {
    this.error$$.pipe(takeUntilDestroyed(this.destoryRef)).subscribe((err) => {
      const detail = err?.error?.error_msg;
      console.error(err);
      this.messageService.add({
        severity: "error",
        summary: this.translocoService.translate("common.toast.error"),
        detail: `${err?.message}${detail ? ` : ${detail}` : ""}`,
        life: 5000,
      });
    });
  }

  withSuspense = <T>(source$: Observable<T>) =>
    withSuspense(source$, {
      error$$: this.error$$,
      loading$$: this.loading$$,
    });

  toast(message: ToastMessageOptions) {
    this.messageService.add(message);
  }
}
