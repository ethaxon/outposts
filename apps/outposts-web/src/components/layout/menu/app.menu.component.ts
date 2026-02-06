import {
	afterNextRender,
	Component,
	computed,
	ElementRef,
	inject,
	type OnDestroy,
} from "@angular/core";
import { NavigationEnd, Router, RouterModule } from "@angular/router";
import { DomHandler } from "primeng/dom";
import type { Subscription } from "rxjs";
import { default as MenuData } from "@/assets/data/menu.json";
import { AppConfigService } from "@/core/servces/app-config.service";
import { AppMenuItemComponent } from "./app.menuitem.component";

export interface MenuItem {
	name?: string;
	icon?: string;
	children?: MenuItem[];
	routerLink?: string;
	href?: string;
	badge?: string;
}

@Component({
	selector: "app-menu",
	template: ` <aside>
          <nav>
            <ol class="layout-menu">
              @for (item of menu; track item; let i = $index) {
                <li app-menuitem [item]="item" [root]="true"></li>
              }
            </ol>
          </nav>
        </aside>`,
	host: {
		class: "layout-sidebar",
		"[class.active]": "isActive()",
	},
	standalone: true,
	imports: [RouterModule, AppMenuItemComponent],
})
export class AppMenuComponent implements OnDestroy {
	menu!: MenuItem[];

	private routerSubscription?: Subscription;
	private configService: AppConfigService = inject(AppConfigService);
	private el: ElementRef = inject(ElementRef);
	private router: Router = inject(Router);

	isActive = computed(() => this.configService.appState().menuActive);

	constructor() {
		this.menu = MenuData.data;

		afterNextRender(() => {
			setTimeout(() => {
				this.scrollToActiveItem();
			}, 1);

			this.routerSubscription = this.router.events.subscribe((event) => {
				if (event instanceof NavigationEnd && this.isActive()) {
					this.configService.hideMenu();
					DomHandler.unblockBodyScroll("blocked-scroll");
				}
			});
		});
	}

	scrollToActiveItem() {
		const activeItem = DomHandler.findSingle(
			this.el.nativeElement,
			".router-link-active",
		);
		if (activeItem && !this.isInViewport(activeItem)) {
			activeItem.scrollIntoView({ block: "center" });
		}
	}

	isInViewport(element: Element) {
		const rect = element.getBoundingClientRect();
		return (
			rect.top >= 0 &&
			rect.left >= 0 &&
			rect.bottom <=
				(window.innerHeight || document.documentElement.clientHeight) &&
			rect.right <= (window.innerWidth || document.documentElement.clientWidth)
		);
	}

	ngOnDestroy() {
		if (this.routerSubscription) {
			this.routerSubscription.unsubscribe();
			this.routerSubscription = undefined;
		}
	}
}
