import { NgModule } from "@angular/core";
import { RouterModule, type Routes } from "@angular/router";
import { DashboardComponent } from "./dashboard/dashboard.component";
import { VlanPageComponent } from "./vlan/vlan-page.component";
import { WorkspaceComponent } from "./workspace/workspace.component";

const routes: Routes = [
  {
    path: "dashboard",
    component: DashboardComponent,
  },
  { path: "vlans", component: VlanPageComponent },
  {
    path: "workspace/:id",
    component: WorkspaceComponent,
  },
  {
    path: "",
    redirectTo: "/confluence/dashboard",
    pathMatch: "full",
  },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [],
})
export class ConfluenceRoutingModule {}
