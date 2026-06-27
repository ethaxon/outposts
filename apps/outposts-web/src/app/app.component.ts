import { afterNextRender, Component, inject, ChangeDetectionStrategy } from "@angular/core";
import { environment } from "@/environments/environment";
import { AppI18nService } from "@/core/servces/app-i18n.service";

@Component({
  selector: "app-root",
  templateUrl: "./app.component.html",
  changeDetection: ChangeDetectionStrategy.Eager,
  standalone: false,
})
export class AppComponent {
  private readonly i18nService = inject(AppI18nService);

  constructor() {
    afterNextRender(() => {
      void this.i18nService;
      if (environment.production) {
        this.injectScripts();
      }
      setTimeout(() => {
        document.body.style.visibility = "visible";
        document.body.style.opacity = "1";
      });

      this.bindRouteEvents();
    });
  }

  injectScripts() {}

  bindRouteEvents() {}
}
