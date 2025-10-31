import { Component, DestroyRef, OnInit, inject, signal } from '@angular/core';
import { ConfluenceService } from '../confluence.service';
import { switchMap } from 'rxjs';
import { ConfluenceDto } from '../bindings/ConfluenceDto';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { AppOverlayService } from '@/core/servces/app-overlay.service';

@Component({
  standalone: false,
  selector: 'app-confluence-dashboard',
  template: `
    <p-dataView #dv [value]="confluences()">
      <ng-template #emptymessage>
        @if (overlayService.loading$$ | async) {
        <div class="p-4">
          <p-skeleton class="mb-2"></p-skeleton>
          <p-skeleton width="10rem" class="mb-2"></p-skeleton>
          <p-skeleton width="5rem" class="mb-2"></p-skeleton>
          <p-skeleton height="2rem" class="mb-2"></p-skeleton>
        </div>
        } @else {
          <div class="flex justify-center align-center py-10">
          <i class="pi pi-inbox" style="font-size: 2.5rem"></i>
        </div>
        }
      </ng-template>
      <ng-template #header>
        <div class="flex justify-between items-center">
          <div class="text-2xl flex items-center h-100">Confluence</div>
          <p-button
            label="Add"
            (click)="addConfluence()"
            icon="pi pi-plus"
            [outlined]="true"
          />
        </div>
      </ng-template>
      <ng-template #list let-items>
        @for (item of items; track $index) {
        <div
          class="flex flex-row items-start p-6 gap-6"
          [ngClass]="{ 'border-top-1': !$first }"
        >
          <p-avatar
            [label]="item.name.slice(0, 1).toUpperCase()"
            class="mr-1"
            size="xlarge"
          ></p-avatar>
          <div
            class="flex justify-between items-center flex-1 gap-6"
          >
            <div
              class="flex flex-col items-start gap-2"
            >
              <div class="text-2xl font-bold text-surface-900 dark:text-surface-0">{{ item.name }}</div>
              <div class="flex items-center gap-4">
                <span class="flex items-center gap-2">
                  <i class="pi pi-user-edit"></i>
                  <span class="font-semibold">{{ item.creator }}</span>
                </span>
                <p-tag
                  [value]="getSeverityText(item)"
                  [severity]="getSeverity(item)"
                  [style]="{
                    background:
                      getSeverityText(item) === 'active'
                        ? 'var(--blue-500)'
                        : 'var(--gray-500)'
                  }"
                ></p-tag>
              </div>
            </div>
            <div class="flex items-center justify-center gap-1">
              <a
                [routerLink]="['/confluence/workspace', item.id]"
                rel="noopener noreferrer"
                class="p-button p-button-rounded p-button-icon-only p-ripple p-button-outlined"
              >
                <i class="pi pi-file-edit"></i>
              </a>
              <p-button
                icon="pi pi-trash"
                [outlined]="true"
                [rounded]="true"
                (click)="removeConfluence(item.id)"
              ></p-button>
            </div>
          </div>
        </div>
        }
      </ng-template>
    </p-dataView>
  `,
  providers: [],
})
export class DashboardComponent implements OnInit {
  protected readonly confluenceService = inject(ConfluenceService);
  protected readonly destoryRef = inject(DestroyRef);
  protected readonly overlayService = inject(AppOverlayService);

  confluences = signal<ConfluenceDto[]>([]);

  ngOnInit() {
    this.overlayService
      .withSuspense(this.confluenceService.getAllConfluences())
      .pipe(takeUntilDestroyed(this.destoryRef))
      .subscribe((data) => {
        this.confluences.set(data);
      });
  }

  async addConfluence() {
    this.overlayService
      .withSuspense(
        this.confluenceService.addConfluence().pipe(
          switchMap(() => this.confluenceService.getAllConfluences()),
          takeUntilDestroyed(this.destoryRef)
        )
      )
      .subscribe((c) => {
        this.confluences.set(c);
        this.overlayService.toast({
          severity: 'success',
          summary: 'Success',
          detail: 'Create successfully',
        });
      });
  }

  getSeverityText(item: ConfluenceDto): string {
    if (item.mux_content && item.profiles.length) {
      return 'active';
    }
    return 'not active';
  }

  getSeverity(_item: ConfluenceDto): 'info' {
    return 'info';
  }

  removeConfluence(id: number) {
    this.overlayService
      .withSuspense(
        this.confluenceService.removeConfluence(id).pipe(
          switchMap(() => this.confluenceService.getAllConfluences()),
          takeUntilDestroyed(this.destoryRef)
        )
      )
      .subscribe((c) => {
        this.confluences.set(c);
        this.overlayService.toast({
          severity: 'success',
          summary: 'Success',
          detail: 'Remove successfully',
        });
      });
  }
}
