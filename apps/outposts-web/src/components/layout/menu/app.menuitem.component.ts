import { CommonModule } from "@angular/common";
import {
  booleanAttribute,
  Component,
  Input,
  inject,
  ChangeDetectionStrategy,
  signal,
} from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { Router, RouterModule } from "@angular/router";
import { NgIcon, provideIcons } from "@ng-icons/core";
import {
  lucideChevronDown,
  lucideCircleHelp,
  lucideCompass,
  lucideHouse,
  lucidePaperclip,
  lucideSearch,
  lucideUsers,
} from "@ng-icons/lucide";
import type { MenuItem } from "./app.menu.component";

@Component({
  selector: "[app-menuitem]",
  templateUrl: "./app.menuitem.component.html",
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule, RouterModule, TranslocoModule, NgIcon],
  providers: [
    provideIcons({
      lucideChevronDown,
      lucideCircleHelp,
      lucideCompass,
      lucideHouse,
      lucidePaperclip,
      lucideSearch,
      lucideUsers,
    }),
  ],
})
export class AppMenuItemComponent {
  @Input() item?: MenuItem;

  @Input({ transform: booleanAttribute }) root = true;

  private router: Router = inject(Router);

  readonly expanded = signal(false);

  isActiveRootMenuItem(menuitem: MenuItem): boolean {
    const url = this.router.url.split("#")[0];
    return (
      !!menuitem.children &&
      !menuitem.children.some(
        (item) =>
          item.routerLink === `${url}` || item.children?.some((it) => it.routerLink === `${url}`),
      )
    );
  }
}
