import { Component } from "@angular/core";

@Component({
	standalone: false,
	selector: "app-doc-layout",
	template: `
      <div #appDocMain class="flex-1 min-w-0">
          <ng-content></ng-content>
      </div>
      <app-doc-toc [contentSourceContent]="appDocMain"></app-doc-toc>
  `,
	host: {
		class: "flex",
	},
})
export class DocLayoutComponent {}
