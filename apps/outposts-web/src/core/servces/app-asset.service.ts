/**
 * source partial from [ngx-script-loader](https://github.com/muratcorlu/ngx-script-loader)
 */
import { Injectable, inject, DOCUMENT } from '@angular/core';
import {
  BehaviorSubject, catchError,
  map,
  Observable,
  tap
} from 'rxjs';
import { take, shareReplay } from 'rxjs/operators';

import { HttpClient } from "@angular/common/http";

@Injectable({
  providedIn: 'root'
})
export class AppAssetService {
  private loaders: { [url: string]: Observable<any> } = {};
  private loaded$: { [url: string]: BehaviorSubject<any | undefined> } = {}
  private readonly document = inject(DOCUMENT);
  private readonly httpClient = inject(HttpClient);

  private _loadScript(url: string, attributes?: {
    [s: string]: string
  }, targetEl: HTMLElement | string = 'head'): Observable<Event> {
    return new Observable<Event>((observer) => {
      const script: HTMLScriptElement = this.document.createElement('script');

      if (attributes) {
        for (const key in attributes) {
          if (Object.prototype.hasOwnProperty.call(attributes, key)) {
            script.setAttribute(key, attributes[key]);
          }
        }
      }

      script.onload = (event: Event) => {
        observer.next(event);
        observer.complete();
      };

      script.onerror = err => {
        observer.error(err);
      };

      script.src = url;

      const targetElement = typeof targetEl === 'string' ? this.document.querySelector(targetEl) : targetEl;
      if (targetElement) {
        targetElement.appendChild(script);
      } else {
        observer.error(`${this.constructor.name} loadScript error, target ${targetElement} not found`);
      }
    });
  }

  private _loadLink(
    url: string, attributes: { [attr: string]: string, rel: string }, targetEl: HTMLElement | string = 'head'
  ) {
    return new Observable<Event>((observer) => {
      const script: HTMLLinkElement = this.document.createElement('link');

      if (attributes) {
        for (const key in attributes) {
          if (Object.prototype.hasOwnProperty.call(attributes, key)) {
            script.setAttribute(key, attributes[key]);
          }
        }
      }

      script.onload = (event: Event) => {
        observer.next(event);
        observer.complete();
      };

      script.onerror = err => {
        observer.error(err);
      };

      script.href = url;

      const targetElement = typeof targetEl === 'string' ? this.document.querySelector(targetEl) : targetEl;
      if (targetElement) {
        targetElement.appendChild(script);
      } else {
        observer.error(`${this.constructor.name} loadLink error, target ${targetElement} not found`);
      }
    });
  }

  private _loadPlainText(
    url: string
  ) {
    return this.httpClient
      .get(url, { responseType: 'text' })
      .pipe(map(arrBuf => arrBuf.toString()))
  }

  private _getLoaded$(url: string): BehaviorSubject<unknown | undefined> {
    return this.loaded$[url] = this.loaded$[url] || new BehaviorSubject(undefined);
  }

  loadScript(url: string, attributes?: Record<string, string>, targetEl: HTMLElement | string = 'head'): Observable<Event> {
    return this.loaders[url] = this.loaders[url] || this._loadScript(url, attributes, targetEl).pipe(
      take(1),
      shareReplay(1),
      tap(value => this._getLoaded$(url).next(value)),
      catchError((e, caught) => {
        this._getLoaded$(url).error(e);
        return caught;
      })
    );
  }

  loadLink(url: string, attributes: {
    [attr: string]: string,
    rel: string
  }, targetEl: HTMLElement | string = 'head'): Observable<Event> {
    return this.loaders[url] = this.loaders[url] || this._loadLink(url, attributes, targetEl).pipe(
      take(1),
      shareReplay(1),
      tap(value => this._getLoaded$(url).next(value)),
      catchError((e, caught) => {
        this._getLoaded$(url).error(e);
        return caught;
      })
    );
  }

  loadPlainText(url: string): Observable<string> {
    return this.loaders[url] = this.loaders[url] || this._loadPlainText(url)
      .pipe(
        take(1),
        shareReplay(1),
        tap(value => this._getLoaded$(url).next(value)),
        catchError((e, caught) => {
          this._getLoaded$(url).error(e);
          return caught;
        })
      )
  }

  isAssetLoaded$(url: string): Observable<boolean> {
    return this._getLoaded$(url)
      .pipe(
        map(loaded => !!loaded),
      )
  }

  isLinkLoaded$(url: string): Observable<boolean> {
    return this.isAssetLoaded$(url);
  }

  isScriptLoaded$(url: string): Observable<boolean> {
    return this.isAssetLoaded$(url);
  }

  isPlainTextLoaded$(url: string): Observable<boolean> {
    return this.isAssetLoaded$(url);
  }
}
