import { NgModule } from "@angular/core";
import { RouterModule, type Routes } from "@angular/router";
import { ConfluencePageComponent } from "./confluence/confluence-page.component";
import { ConfluencesPageComponent } from "./confluences/confluences-page.component";
import { SupplicantsPageComponent } from "./supplicants/supplicants-page.component";
import { VlansPageComponent } from "./vlans/vlans-page.component";

const routes: Routes = [
  { path: "confluences", component: ConfluencesPageComponent },
  { path: "confluence/:id", component: ConfluencePageComponent },
  { path: "vlans", component: VlansPageComponent },
  { path: "supplicants", component: SupplicantsPageComponent },
  // Former paths, kept so existing bookmarks and post-login redirects still land.
  { path: "dashboard", redirectTo: "confluences" },
  { path: "workspace/:id", redirectTo: "confluence/:id" },
  { path: "", redirectTo: "confluences", pathMatch: "full" },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [],
})
export class ConfluenceRoutingModule {}
