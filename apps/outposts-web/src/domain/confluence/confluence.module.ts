import { NgModule } from "@angular/core";
import { provideIcons } from "@ng-icons/core";
import {
  lucideCheck,
  lucideCircleAlert,
  lucideCloudOff,
  lucideCopy,
  lucideEye,
  lucideFilePenLine,
  lucideHouse,
  lucideKeyRound,
  lucideLayers,
  lucideLoaderCircle,
  lucideLock,
  lucideLockOpen,
  lucidePencil,
  lucidePlay,
  lucidePlus,
  lucideRefreshCw,
  lucideSlidersVertical,
  lucideTrash2,
  lucideX,
} from "@ng-icons/lucide";
import { ClipboardModule } from "@/tools/clipboard/clipboard.module";
import { QrcodeModule } from "@/tools/qrcode/qrcode.module";
import { ConfluenceService } from "./confluence.service";
import { ConfluenceRoutingModule } from "./confluence-rounting.module";

/**
 * Lazy route boundary for `/confluence/*`. Every page is a standalone component; this
 * module only supplies the shared services and icons to the lazy injector.
 */
@NgModule({
  providers: [
    ConfluenceService,
    provideIcons({
      lucideCheck,
      lucideCircleAlert,
      lucideCloudOff,
      lucideCopy,
      lucideEye,
      lucideFilePenLine,
      lucideHouse,
      lucideKeyRound,
      lucideLayers,
      lucideLoaderCircle,
      lucideLock,
      lucideLockOpen,
      lucidePencil,
      lucidePlay,
      lucidePlus,
      lucideRefreshCw,
      lucideSlidersVertical,
      lucideTrash2,
      lucideX,
    }),
  ],
  imports: [ConfluenceRoutingModule, ClipboardModule, QrcodeModule],
})
export class ConfluenceModule {}
