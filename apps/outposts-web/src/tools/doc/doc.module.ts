import { CommonModule } from "@angular/common";
import { HttpClient } from "@angular/common/http";
import { NgModule, SecurityContext } from "@angular/core";
import { NgIcon, provideIcons } from "@ng-icons/core";
import { TranslocoModule } from "@jsverse/transloco";
import { lucideArrowUp, lucideCopy } from "@ng-icons/lucide";
import { RouterLink } from "@angular/router";
import { gfmHeadingId } from "marked-gfm-heading-id";
import { MARKED_EXTENSIONS, MARKED_OPTIONS, MarkdownModule, SANITIZE } from "ngx-markdown";
import { HlmButton } from "@/components/ui/button";
import { AppSkeletonComponent } from "../../components/ui/app-skeleton.component";
import { DocClipboardButtonComponent } from "@/tools/doc/components/clipboard-button/doc-clipboard-button.component";
import { DocLayoutComponent } from "@/tools/doc/components/layout/doc-layout.component";
import { DocSectionComponent } from "@/tools/doc/components/section/doc-section.component";
import { DocTableOfContentsComponent } from "@/tools/doc/components/table-of-contents/doc-table-of-contents.component";
import { DocTableOfContentsLoader } from "@/tools/doc/services/doc-table-of-contents-loader.service";
import { DocTableOfContentsSpy } from "@/tools/doc/services/doc-table-of-contents-spy.service";
import { DocService } from "./services/doc.service";

@NgModule({
  providers: [
    DocService,
    DocTableOfContentsLoader,
    DocTableOfContentsSpy,
    provideIcons({ lucideArrowUp, lucideCopy }),
  ],
  declarations: [
    DocSectionComponent,
    DocClipboardButtonComponent,
    DocTableOfContentsComponent,
    DocLayoutComponent,
  ],
  exports: [
    DocSectionComponent,
    DocClipboardButtonComponent,
    DocTableOfContentsComponent,
    DocLayoutComponent,
  ],
  imports: [
    CommonModule,
    HlmButton,
    TranslocoModule,
    NgIcon,
    AppSkeletonComponent,
    RouterLink,
    MarkdownModule.forRoot({
      loader: HttpClient,
      sanitize: {
        provide: SANITIZE,
        useValue: SecurityContext.NONE,
      },
      markedExtensions: [
        {
          provide: MARKED_EXTENSIONS,
          useFactory: gfmHeadingId,
          multi: true,
        },
      ],
      markedOptions: {
        provide: MARKED_OPTIONS,
        useValue: {
          gfm: true,
        },
      },
    }),
  ],
})
export class DocModule {}
