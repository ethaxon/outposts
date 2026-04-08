import type { Routes } from "@angular/router";
import { AppMainComponent } from "@/components/layout/app.main.component";
import { canActiveConfluence } from "@/domain/confluence/confluence-can-active.guard";
import { LandingComponent } from "@/pages/landing/landing.component";

export const routes: Routes = [
  { path: "", component: LandingComponent, pathMatch: "full" },
  { path: "apps", redirectTo: "/confluence", pathMatch: "full" },
  {
    path: "",
    component: AppMainComponent,
    children: [
      {
        path: "confluence",
        canActivate: [canActiveConfluence],
        loadChildren: () =>
          import(
            /* webpackChunkName: "confluence-module" */ "../domain/confluence/confluence.module"
          ).then((m) => m.ConfluenceModule),
      },
    ],
  },
  { path: "notfound", loadChildren: () => import("@/pages/notfound/routes") },
  { path: "**", redirectTo: "/notfound" },
];
