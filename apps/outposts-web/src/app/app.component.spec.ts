import { TestBed } from "@angular/core/testing";
import { RouterModule } from "@angular/router";
import { AppComponent } from "./app.component";

describe("AppComponent", () => {
	beforeEach(async () => {
		await TestBed.configureTestingModule({
			imports: [AppComponent, RouterModule.forRoot([])],
		}).compileComponents();
	});

	it("should render title", () => {
		const fixture = TestBed.createComponent(AppComponent);
		fixture.detectChanges();
		const compiled = fixture.nativeElemdent as HTMLElement;
		expect(compiled.querySelector("h1")?.textContent).toContain(
			"Welcome outposts-web",
		);
	});
});
