import { CommonModule } from "@angular/common";
import { booleanAttribute, Component, Input, inject } from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { Router, RouterModule } from "@angular/router";
import { StyleClass } from "primeng/styleclass";
import { Tag } from "primeng/tag";
import type { MenuItem } from "./app.menu.component";

@Component({
  selector: "[app-menuitem]",
  templateUrl: "./app.menuitem.component.html",
  standalone: true,
  imports: [CommonModule, StyleClass, RouterModule, Tag, TranslocoModule],
})
export class AppMenuItemComponent {
  @Input() item?: MenuItem;

  @Input({ transform: booleanAttribute }) root = true;

  private router: Router = inject(Router);

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
