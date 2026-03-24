import {
  catchError,
  finalize,
  from,
  type Observable,
  type Subject,
  switchMap,
  take,
  throwError,
} from "rxjs";

export function withSuspense<T, E = any>(
  source$: Observable<T>,
  {
    loading$$,
    error$$,
    takeFirst = true,
  }: {
    loading$$?: Subject<boolean>;
    error$$?: Subject<E>;
    takeFirst?: boolean;
  } = {},
): Observable<T> {
  if (loading$$) {
    loading$$.next(true);
  }

  let ob$ = source$;

  if (takeFirst) {
    ob$ = ob$.pipe(take(1));
  }

  return ob$.pipe(
    catchError((err) => {
      if (error$$) {
        error$$.next(err);
      }
      return throwError(() => err);
    }),
    finalize(() => {
      if (loading$$) {
        loading$$.next(false);
      }
    }),
  );
}

export function switchMapWithSuspense<T, U, E = any>(
  fn: (s: T) => Observable<U>,
  options: {
    loading$$?: Subject<boolean>;
    error$$?: Subject<E>;
  } = {},
) {
  return (source$: Observable<T>): Observable<U> =>
    source$.pipe(switchMap((s) => withSuspense(from(fn(s)), options)));
}
