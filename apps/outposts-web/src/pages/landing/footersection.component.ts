import { Component } from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { RouterModule } from "@angular/router";

@Component({
  selector: "app-footer-section",
  standalone: true,
  imports: [RouterModule, TranslocoModule],
  templateUrl: "./footersection.component.html",
})
export class FooterSectionComponent {}
