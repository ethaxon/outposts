import { Component, ChangeDetectionStrategy } from "@angular/core";

@Component({
  standalone: false,
  selector: "app-doc-layout",
  templateUrl: "./doc-layout.component.html",
  changeDetection: ChangeDetectionStrategy.Eager,
  host: {
    class: "flex",
  },
})
export class DocLayoutComponent {}
