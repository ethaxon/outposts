import { CommonModule } from "@angular/common";
import { NgModule } from "@angular/core";
import { FormsModule, ReactiveFormsModule } from "@angular/forms";
import { RouterModule } from "@angular/router";
import { MonacoEditorModule } from "ngx-monaco-editor-v2";
import { AvatarModule } from "primeng/avatar";
import { BreadcrumbModule } from "primeng/breadcrumb";
import { ButtonModule } from "primeng/button";
import { CardModule } from "primeng/card";
import { CheckboxModule } from "primeng/checkbox";
import { DataViewModule } from "primeng/dataview";
import { DialogModule } from "primeng/dialog";
import { InputTextModule } from "primeng/inputtext";
import { PanelModule } from "primeng/panel";
import { ScrollTopModule } from "primeng/scrolltop";
import { SkeletonModule } from "primeng/skeleton";
import { TagModule } from "primeng/tag";
import { ClipboardModule } from "@/tools/clipboard/clipboard.module";
import { DocModule } from "@/tools/doc/doc.module";
import { QrcodeModule } from "@/tools/qrcode/qrcode.module";
import { ConfluenceService } from "./confluence.service";
import { ConfluenceRoutingModule } from "./confluence-rounting.module";
import { DashboardComponent } from "./dashboard/dashboard.component";
import { WorkspaceComponent } from "./workspace/workspace.component";

@NgModule({
	declarations: [DashboardComponent, WorkspaceComponent],
	providers: [ConfluenceService],
	imports: [
		BreadcrumbModule,
		CommonModule,
		ConfluenceRoutingModule,
		DocModule,
		ScrollTopModule,
		DataViewModule,
		TagModule,
		ButtonModule,
		CardModule,
		AvatarModule,
		PanelModule,
		RouterModule,
		FormsModule,
		MonacoEditorModule,
		DialogModule,
		ReactiveFormsModule,
		InputTextModule,
		ClipboardModule,
		QrcodeModule,
		SkeletonModule,
		CheckboxModule,
	],
})
export class ConfluenceModule {}
