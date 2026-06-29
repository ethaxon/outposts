import { DestroyRef, Injectable, inject } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { TranslocoService } from "@jsverse/transloco";
import { toast } from "@spartan-ng/brain/sonner";
import { BehaviorSubject, type Observable, Subject } from "rxjs";
import { withSuspense } from "@/tools/rx";

@Injectable()
export class AppOverlayService {
  protected readonly destoryRef = inject(DestroyRef);
  protected readonly translocoService = inject(TranslocoService);
  readonly error$$ = new Subject<any>();
  readonly loading$$ = new BehaviorSubject<boolean>(false);

  constructor() {
    this.error$$.pipe(takeUntilDestroyed(this.destoryRef)).subscribe((err) => {
      const detail = err?.error?.error_msg;
      console.error(err);
      this.toast({
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

  toast(message: {
    severity?: "success" | "info" | "warn" | "error";
    summary?: string;
    detail?: string;
    life?: number;
  }) {
    const content = message.detail ?? message.summary ?? "";
    const options = {
      description: message.detail ? message.summary : undefined,
      duration: message.life,
    };
    if (message.severity === "error") return toast.error(content, options);
    if (message.severity === "success") return toast.success(content, options);
    if (message.severity === "warn") return toast.warning(content, options);
    return toast.info(content, options);
  }
}
