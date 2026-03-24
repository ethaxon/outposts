import { DOCUMENT } from "@angular/common";
import { computed, effect, Injectable, inject } from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import { TranslocoService } from "@jsverse/transloco";
import { AVAILABLE_LANGS, DEFAULT_LANG, type AppLang } from "@/app/transloco-config";
import { AppConfigService } from "@/core/servces/app-config.service";

const LANG_LABELS: Record<AppLang, string> = {
  en: "English",
  zh_CN: "简体中文",
};

@Injectable({
  providedIn: "root",
})
export class AppI18nService {
  private readonly document = inject(DOCUMENT);
  private readonly appConfigService = inject(AppConfigService);
  private readonly translocoService = inject(TranslocoService);

  readonly availableLangs = AVAILABLE_LANGS.map((id) => ({
    id,
    label: LANG_LABELS[id],
  }));

  readonly activeLang = computed(() => this.normalizeLang(this.appConfigService.appState()?.lang));
  readonly activeLangLabel = computed(() => LANG_LABELS[this.activeLang()]);

  constructor() {
    effect(() => {
      const lang = this.activeLang();
      this.translocoService.setActiveLang(lang);
      this.document.documentElement.lang = lang === "zh_CN" ? "zh-CN" : "en";
    });
  }

  setLanguage(lang: AppLang) {
    this.appConfigService.appState.update((state) => ({
      ...state,
      lang,
    }));
  }

  translate(key: string, params?: Record<string, string | number>) {
    return this.translocoService.translate(key, params);
  }

  translateSignal(key: string, params?: Record<string, string | number>) {
    return toSignal(this.translocoService.selectTranslate(key, params), { initialValue: "" });
  }

  private normalizeLang(lang?: string): AppLang {
    if (lang && AVAILABLE_LANGS.includes(lang as AppLang)) {
      return lang as AppLang;
    }

    return DEFAULT_LANG;
  }
}
