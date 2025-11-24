import { environment } from '@/environments/environment';
import { Component } from '@angular/core';

@Component({
    selector: 'app-footer',
    standalone: true,
    template: `
        <div class="layout-footer">
            <div>
                <span>OUTPOSTS {{ version }} by </span>
                <a href="https://github.com/ethaxon">ethaxon</a>
            </div>
        </div>
    `
})
export class AppFooterComponent {
    version = environment.APP_VERSION;
}
