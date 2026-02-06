import { CommonModule } from "@angular/common";
import { booleanAttribute, Component, Input, inject } from "@angular/core";
import { Router, RouterModule } from "@angular/router";
import { StyleClass } from "primeng/styleclass";
import { Tag } from "primeng/tag";
import type { MenuItem } from "./app.menu.component";

@Component({
	// eslint-disable-next-line
	selector: "[app-menuitem]",
	template: `
       @if (item) {
         @if (root && item.children) {
           <button pButton type="button" class="px-link" pStyleClass="@next" enterFromClass="hidden" enterActiveClass="animate-slidedown" leaveToClass="hidden" leaveActiveClass="animate-slideup">
             <div class="menu-icon">
               <i [ngClass]="item.icon"></i>
             </div>
             <span>{{ item.name }}</span>
             <i class="menu-toggle-icon pi pi-angle-down"></i>
           </button>
         }
         @if (item && item.href) {
           <a [href]="item.href" target="_blank" rel="noopener noreferrer">
             @if (item.icon && root) {
               <div class="menu-icon">
                 <i [ngClass]="item.icon"></i>
               </div>
             }
             <span>{{ item.name }}</span>
             @if (item.badge) {
               <p-tag [value]="item.badge" />
             }
           </a>
         }
         @if (item.routerLink) {
           <a [routerLink]="item.routerLink" routerLinkActive="router-link-active" [routerLinkActiveOptions]="{ paths: 'exact', queryParams: 'ignored', matrixParams: 'ignored', fragment: 'ignored' }">
             @if (item.icon && root) {
               <div class="menu-icon">
                 <i [ngClass]="item.icon"></i>
               </div>
             }
             <span>{{ item.name }}</span>
             @if (item.badge) {
               <p-tag [value]="item.badge" />
             }
           </a>
         }
         @if (!root && item.children) {
           <span class="menu-child-category">{{ item.name }}</span>
         }
         @if (item.children) {
           <div class="overflow-y-hidden transition-all duration-[400ms] ease-in-out" [ngClass]="{ hidden: item.children && root && isActiveRootMenuItem(item) }">
             <ol>
               @for (child of item.children; track child) {
                 <li app-menuitem [root]="false" [item]="child"></li>
               }
             </ol>
           </div>
         }
       }
       `,
	standalone: true,
	imports: [CommonModule, StyleClass, RouterModule, Tag],
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
					item.routerLink === `${url}` ||
					item.children?.some((it) => it.routerLink === `${url}`),
			)
		);
	}
}
