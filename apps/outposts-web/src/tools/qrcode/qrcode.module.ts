import { CommonModule } from "@angular/common";
import { NgModule } from "@angular/core";
import { QrcodeService } from "./qrcode.service";

@NgModule({
  providers: [QrcodeService],
  declarations: [],
  exports: [],
  imports: [CommonModule],
})
export class QrcodeModule {}
