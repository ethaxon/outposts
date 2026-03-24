import {
  afterNextRender,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Component,
  inject,
} from "@angular/core";
import { FormsModule } from "@angular/forms";
import News from "@/assets/data/news.json";
import { AppConfigService } from "@/core/servces/app-config.service";

@Component({
  selector: "app-news",
  standalone: true,
  templateUrl: "./app.news.component.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule],
})
export class AppNewsComponent {
  storageKey = "outposts-banner-news";

  announcement: any;

  private configService = inject(AppConfigService);
  private cd = inject(ChangeDetectorRef);

  constructor() {
    afterNextRender(() => {
      const itemString = localStorage.getItem(this.storageKey);

      if (itemString) {
        const item = JSON.parse(itemString);

        if (!item.hiddenNews || item.hiddenNews !== News.id) {
          this.configService.newsActive.set(true);
          this.announcement = News;
        } else {
          this.configService.newsActive.set(false);
        }
      } else {
        this.configService.newsActive.set(true);
        this.announcement = News;
      }
      this.cd.markForCheck();
    });
  }

  get isNewsActive(): boolean {
    return this.configService.newsActive();
  }

  hideNews() {
    this.configService.hideNews();
    const item = {
      hiddenNews: this.announcement.id,
    };

    localStorage.setItem(this.storageKey, JSON.stringify(item));
  }
}
