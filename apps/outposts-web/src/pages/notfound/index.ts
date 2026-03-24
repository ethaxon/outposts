import { Component } from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { RouterModule } from "@angular/router";
import { ButtonModule } from "primeng/button";

@Component({
  standalone: true,
  imports: [ButtonModule, RouterModule, TranslocoModule],
  templateUrl: "./index.component.html",
})
export class NotFoundDemoComponent {}
