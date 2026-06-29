import { CommonModule } from "@angular/common";
import { NgModule } from "@angular/core";
import { TranslocoModule } from "@jsverse/transloco";
import { FormsModule, ReactiveFormsModule } from "@angular/forms";
import { RouterModule } from "@angular/router";
import { NgIcon, provideIcons } from "@ng-icons/core";
import {
  lucideCheck,
  lucideCopy,
  lucideEye,
  lucideFilePenLine,
  lucideHouse,
  lucideInbox,
  lucidePencil,
  lucidePlay,
  lucidePlus,
  lucideRefreshCw,
  lucideSlidersVertical,
  lucideTrash2,
  lucideUserRoundPen,
  lucideX,
} from "@ng-icons/lucide";
import { MonacoEditorModule } from "ngx-monaco-editor-v2";
import { HlmAvatarImports } from "@/components/ui/avatar";
import { HlmBadge } from "@/components/ui/badge";
import { HlmButton } from "@/components/ui/button";
import { HlmBreadcrumbImports } from "@/components/ui/breadcrumb";
import { HlmCheckboxImports } from "@/components/ui/checkbox";
import { HlmInputImports } from "@/components/ui/input";
import { HlmSkeleton } from "@/components/ui/skeleton";
import { HlmProgress, HlmProgressIndicator } from "@/components/ui/progress";
import { HlmSelectImports } from "@/components/ui/select";
import { AppDialogComponent } from "../../components/ui/app-dialog.component";
import { AppActionComponent } from "../../components/ui/app-action.component";
import { AppCardComponent } from "../../components/ui/app-card.component";
import { ClipboardModule } from "@/tools/clipboard/clipboard.module";
import { DocModule } from "@/tools/doc/doc.module";
import { QrcodeModule } from "@/tools/qrcode/qrcode.module";
import { ConfluenceService } from "./confluence.service";
import { ConfluenceRoutingModule } from "./confluence-rounting.module";
import { DashboardComponent } from "./dashboard/dashboard.component";
import { WorkspaceComponent } from "./workspace/workspace.component";

@NgModule({
  declarations: [DashboardComponent, WorkspaceComponent],
  providers: [
    ConfluenceService,
    provideIcons({
      lucideCheck,
      lucideCopy,
      lucideEye,
      lucideFilePenLine,
      lucideHouse,
      lucideInbox,
      lucidePencil,
      lucidePlay,
      lucidePlus,
      lucideRefreshCw,
      lucideSlidersVertical,
      lucideTrash2,
      lucideUserRoundPen,
      lucideX,
    }),
  ],
  imports: [
    CommonModule,
    ConfluenceRoutingModule,
    DocModule,
    ...HlmAvatarImports,
    HlmBadge,
    HlmButton,
    ...HlmBreadcrumbImports,
    ...HlmCheckboxImports,
    ...HlmInputImports,
    HlmSkeleton,
    HlmProgress,
    HlmProgressIndicator,
    ...HlmSelectImports,
    NgIcon,
    AppDialogComponent,
    AppActionComponent,
    AppCardComponent,
    RouterModule,
    FormsModule,
    MonacoEditorModule,
    ReactiveFormsModule,
    ClipboardModule,
    QrcodeModule,
    TranslocoModule,
  ],
})
export class ConfluenceModule {}
