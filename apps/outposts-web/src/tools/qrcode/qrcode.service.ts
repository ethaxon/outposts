import { Injectable } from "@angular/core";
import { toDataURL } from "qrcode";

@Injectable()
export class QrcodeService {
	toDataURL(url: string): Promise<string> {
		return toDataURL(url);
	}
}
