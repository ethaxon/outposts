import { Component } from "@angular/core";

@Component({
  standalone: false,
  selector: "app-doc-layout",
  templateUrl: "./doc-layout.component.html",
  host: {
    class: "flex",
  },
})
export class DocLayoutComponent {}
