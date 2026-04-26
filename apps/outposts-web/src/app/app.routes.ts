import type { Routes } from "@angular/router";
import { AppMainComponent } from "@/components/layout/app.main.component";
import {
  createFrontendOidcLoginRedirectHandler,
  TokenSetCallbackComponent,
  secureRouteRoot,
} from "@securitydept/token-set-context-client-angular";
import { LandingComponent } from "@/pages/landing/landing.component";
import { AuthCallbackRouteSegment, AuthClientKey } from "@/domain/auth/auth.defs";

export const routes: Routes = [
  { path: "", component: LandingComponent, pathMatch: "full" },
  { path: AuthCallbackRouteSegment, component: TokenSetCallbackComponent },
  { path: "apps", redirectTo: "/confluence", pathMatch: "full" },
  // Secured route tree using the canonical secureRouteRoot() / secureRoute()
  // contract from @securitydept/token-set-context-client-angular.
  //
  // Root-level runtime policy (requirementHandlers, onUnauthenticated) lives
  // here; child routes only declare serializable requirement metadata.
  {
    path: "",
    component: AppMainComponent,
    children: [
      secureRouteRoot(
        "confluence",
        {
          requirementHandlers: {
            frontend_oidc: createFrontendOidcLoginRedirectHandler({
              clientKey: AuthClientKey.Confluence,
            }),
          },
          requirements: [
            {
              id: "confluence-oidc",
              kind: "frontend_oidc",
              label: "Confluence OIDC",
            },
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
