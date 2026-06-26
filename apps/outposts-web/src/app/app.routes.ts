import type { Routes } from "@angular/router";
import { AppMainComponent } from "@/components/layout/app.main.component";
import { secureTokenSetRouteRoot } from "@securitydept/token-set-context-client-angular";
import { TokenSetClientRegistryAuthRequirement } from "@securitydept/token-set-context-client/registry";
import { LandingComponent } from "@/pages/landing/landing.component";
import { AuthCallbackRouteSegment, AuthClientKey } from "@/domain/auth/auth.defs";
import { AuthCallbackComponent } from "@/domain/auth/auth-callback.component";

export const routes: Routes = [
  { path: "", component: LandingComponent, pathMatch: "full" },
  { path: AuthCallbackRouteSegment, component: AuthCallbackComponent },
  { path: "apps", redirectTo: "/confluence", pathMatch: "full" },
  // Secured route tree using the canonical secureTokenSetRouteRoot() contract.
  // contract from @securitydept/token-set-context-client-angular.
  //
  // Root-level runtime policy (requirementHandlers, onUnauthenticated) lives
  // here; child routes only declare serializable requirement metadata.
  {
    path: "",
    component: AppMainComponent,
    children: [
      secureTokenSetRouteRoot(
        "confluence",
        {
          requirements: [
            TokenSetClientRegistryAuthRequirement.create({
              id: "confluence-oidc",
              label: "Confluence OIDC",
              query: { clientKey: AuthClientKey.Confluence },
            }),
          ],
        },
        {
          loadChildren: () =>
            import(
              /* webpackChunkName: "confluence-module" */ "../domain/confluence/confluence.module"
            ).then((m) => m.ConfluenceModule),
        },
      ),
    ],
  },
  { path: "notfound", loadChildren: () => import("@/pages/notfound/routes") },
  { path: "**", redirectTo: "/notfound" },
];
