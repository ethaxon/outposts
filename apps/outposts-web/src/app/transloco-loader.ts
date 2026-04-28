import { HttpClient } from "@angular/common/http";
import { Injectable, inject } from "@angular/core";
import type { Translation, TranslocoLoader } from "@jsverse/transloco";
import { environment } from "@/environments/environment";

@Injectable({ providedIn: "root" })
export class TranslocoHttpLoader implements TranslocoLoader {
  private http = inject(HttpClient);

  getTranslation(lang: string) {
    const version = environment.production ? environment.APP_VERSION : Date.now().toString();
    return this.http.get<Translation>(`/i18n/${lang}.json?v=${encodeURIComponent(version)}`);
  }
}
