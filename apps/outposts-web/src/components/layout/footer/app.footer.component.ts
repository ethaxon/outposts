import { Component, ChangeDetectionStrategy } from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { environment } from "@/environments/environment";

@Component({
  selector: "app-footer",
  standalone: true,
  imports: [TranslocoModule],
  changeDetection: ChangeDetectionStrategy.Eager,
  templateUrl: "./app.footer.component.html",
})
export class AppFooterComponent {
  version = environment.APP_VERSION;
}
