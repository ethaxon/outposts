import { ChangeDetectionStrategy, Component } from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { NgIcon, provideIcons } from "@ng-icons/core";
import { lucideHouse } from "@ng-icons/lucide";
import { HlmBreadcrumbImports } from "@/components/ui/breadcrumb";
import { VlanCatalogComponent } from "./vlan-catalog.component";

/**
 * Route shell for `/confluence/vlans`. The breadcrumb, title and page card render
 * immediately (like `workspace/:id`), so only the catalog grids show loading state.
 */
@Component({
  selector: "app-vlan-page",
  imports: [TranslocoModule, NgIcon, ...HlmBreadcrumbImports, VlanCatalogComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  viewProviders: [provideIcons({ lucideHouse })],
  template: `
    <nav hlmBreadcrumb [attr.aria-label]="'common.navigation.breadcrumb' | transloco">
      <ol hlmBreadcrumbList>
        <li hlmBreadcrumbItem>
          <a
            hlmBreadcrumbLink
            [link]="['/']"
            [attr.aria-label]="'common.navigation.home' | transloco"
          >
            <ng-icon name="lucideHouse" aria-hidden="true" />
          </a>
        </li>
        <li hlmBreadcrumbSeparator></li>
        <li hlmBreadcrumbItem>
          <a hlmBreadcrumbLink [link]="['/confluence']">{{
            "confluence.workspace.breadcrumb.confluence" | transloco
          }}</a>
        </li>
        <li hlmBreadcrumbSeparator></li>
        <li hlmBreadcrumbItem>
          <span hlmBreadcrumbPage>{{ "confluence.workspace.vlan.title" | transloco }}</span>
        </li>
      </ol>
    </nav>
    <section class="mt-2 mb-4 min-w-0 rounded-lg border bg-card p-4 sm:p-6">
      <header class="px-2">
        <h1 class="text-2xl font-bold">{{ "confluence.workspace.vlan.title" | transloco }}</h1>
        <p class="mt-1 text-sm text-muted-foreground">
          {{ "confluence.workspace.vlan.pageDescription" | transloco }}
        </p>
      </header>
      <app-vlan-catalog />
    </section>
  `,
})
export class VlanPageComponent {}
