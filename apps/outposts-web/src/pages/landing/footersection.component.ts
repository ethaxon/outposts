import { Component, ChangeDetectionStrategy } from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { RouterModule } from "@angular/router";
import { NgIcon, provideIcons } from "@ng-icons/core";
import {
  lucideGithub,
  lucideMail,
  lucideMessageCircle,
  lucideMessagesSquare,
  lucideSend,
} from "@ng-icons/lucide";

@Component({
  selector: "app-footer-section",
  standalone: true,
  imports: [RouterModule, TranslocoModule, NgIcon],
  providers: [
    provideIcons({
      lucideGithub,
      lucideSend,
      lucideMessageCircle,
      lucideMail,
      lucideMessagesSquare,
    }),
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: "./footersection.component.html",
})
export class FooterSectionComponent {}
