import { Component, DestroyRef, inject, type OnInit } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import {
	FormBuilder,
	type FormControl,
	type FormGroup,
	Validators,
} from "@angular/forms";
import { ActivatedRoute } from "@angular/router";
import { RxwebValidators } from "@rxweb/reactive-form-validators";
import { pascalCase } from "change-case";
import { format } from "date-fns";
import { isEqual } from "es-toolkit";
import type { editor as MonacoEditor } from "monaco-editor";
import {
	BehaviorSubject,
	catchError,
	combineLatestWith,
	distinctUntilChanged,
	EMPTY,
	filter,
	map,
	shareReplay,
	skip,
	switchMap,
	take,
	tap,
	withLatestFrom,
} from "rxjs";
import { AppConfigService } from "@/core/servces/app-config.service";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import { ClipboardService } from "@/tools/clipboard/clipboard.service";
import { QrcodeService } from "@/tools/qrcode/qrcode.service";
import type { RecursiveNonNullable } from "@/tools/type-assert";
import type { ConfluenceDto } from "../bindings/ConfluenceDto";
import type { ProfileDto } from "../bindings/ProfileDto";
import type { SubscribeSourceDto } from "../bindings/SubscribeSourceDto";
import type { SubscribeSourceUpdateDto } from "../bindings/SubscribeSourceUpdateDto";
import { ConfluenceService } from "../confluence.service";
import { hourPlusLevelCronExprValidator } from "../validators/cron-expr.validators";

@Component({
	standalone: false,
	selector: "app-confluence-workspace",
	templateUrl: "./workspace.component.html",
	styles: `
    :host ::ng-deep {
      .p-breadcrumb {
        background-color: transparent;
        border: none;
      }

      .confluence-subscribe-source-item {
        min-width: 9em;

        .p-card-content {
          padding: 0;
        }
      }

      .confluence-profile-item {
        min-width: 9em;

        .p-card-content {
          padding: 0;
        }
      }
    }

    .confluence-subscribe-source-item {
      p-button {
        right: 0;
        top: 0;
      }
    }

    .profile-url {
      margin-top: 0.5rem;
      word-break: break-all;
    }
  `,
})
export class WorkspaceComponent implements OnInit {
	protected readonly confluenceService = inject(ConfluenceService);
	protected readonly route = inject(ActivatedRoute);
	protected readonly appConfigService = inject(AppConfigService);
	protected readonly destoryRef = inject(DestroyRef);
	protected readonly overlayService = inject(AppOverlayService);
	protected readonly fb = inject(FormBuilder);
	protected readonly confluenceId$ = this.route.params.pipe(
		map((params) => parseInt(params.id, 10)),
		distinctUntilChanged(),
		shareReplay(1),
	);
	protected readonly clipboardService = inject(ClipboardService);
	protected readonly qrcodeService = inject(QrcodeService);

	confluence$ = new BehaviorSubject<ConfluenceDto | undefined>(undefined);
	confluenceName$ = this.confluence$.pipe(
		map((c) => `${c?.name ?? ""}`.toLocaleUpperCase()),
	);
	protected tmplEditorOptions: MonacoEditor.IStandaloneEditorConstructionOptions =
		{
			theme: this.appConfigService.theme() === "dark" ? "vs-dark" : "vs",
			language: "yaml",
			automaticLayout: true,
		};
	tmpl = "";
	profiles: ProfileDto[] = [];
	subscribeSources: SubscribeSourceDto[] = [];
	subscribeSourceCreation?: {
		value: {
			confluence_id: number;
		};
		form: FormGroup<{
			url: FormControl<string | null>;
			name: FormControl<string | null>;
			proxy_server: FormControl<string | null>;
			proxy_auth: FormControl<string | null>;
			passive_sync: FormControl<boolean | null>;
		}>;
	};
	subscribeSourceUpdate?: {
		value: {
			id: number;
		};
		form: FormGroup<{
			url: FormControl<string | null>;
			name: FormControl<string | null>;
			passive_sync: FormControl<boolean | null>;
			proxy_server: FormControl<string | null>;
			proxy_auth: FormControl<string | null>;
		}>;
	};
	muxContentPreview?: {
		content: string;
	};
	subscribeSourceContentPreview?: {
		content: string;
		id: number;
	};
	urlPreview?: {
		url: string;
		qrcodeDataUrl?: string;
	};
	cronUpdateForm = this.fb.group({
		cronExpr: this.fb.control("", [hourPlusLevelCronExprValidator]),
	});
	uaUpdateForm = this.fb.group({
		userAgent: this.fb.control("", []),
	});
	nameUpdateDialog?: {
		form: FormGroup<{
			name: FormControl<string | null>;
		}>;
	};

	breadcrumb = {
		items: [
			{ label: "Confluence", routerLink: ["/confluence"] },
			{ label: "Workspace" },
		],
		home: { icon: "pi pi-home", routerLink: "/" },
	};

	ngOnInit() {
		this.confluenceId$
			.pipe(
				switchMap((id) =>
					this.overlayService
						.withSuspense(this.confluenceService.getConfluenceById(id))
						.pipe(catchError((_) => EMPTY)),
				),
				takeUntilDestroyed(this.destoryRef),
			)
			.subscribe(this.confluence$);

		this.confluence$
			.pipe(
				map((c) => c?.template ?? ""),
				distinctUntilChanged(),
				takeUntilDestroyed(this.destoryRef),
			)
			.subscribe((tmpl) => { this.tmpl = tmpl; });

		this.confluence$
			.pipe(
				map((c) => c?.subscribe_sources ?? []),
				distinctUntilChanged(isEqual),
				takeUntilDestroyed(this.destoryRef),
			)
			.subscribe((ss) => { this.subscribeSources = ss; });

		this.confluence$
			.pipe(
				map((c) => c?.profiles ?? ""),
				distinctUntilChanged(isEqual),
				takeUntilDestroyed(this.destoryRef),
			)
			.subscribe((ps) => { this.profiles = ps; });

		this.confluence$
			.pipe(
				map((c) => c?.cron_expr ?? ""),
				distinctUntilChanged(),
				filter((v) => v !== this.cronUpdateForm.value.cronExpr),
				takeUntilDestroyed(this.destoryRef),
			)
			.subscribe((expr) => {
				this.cronUpdateForm.patchValue({
					cronExpr: expr,
				});
			});

		this.confluence$
			.pipe(
				map((c) => c?.user_agent ?? ""),
				distinctUntilChanged(),
				filter((v) => v !== this.uaUpdateForm.value.userAgent),
				takeUntilDestroyed(this.destoryRef),
			)
			.subscribe((ua) => {
				this.uaUpdateForm.patchValue({
					userAgent: ua,
				});
			});

		this.appConfigService.theme$
			.pipe(skip(1), takeUntilDestroyed(this.destoryRef))
			.subscribe((theme) => {
				this.tmplEditorOptions = {
					theme: theme === "dark" ? "vs-dark" : "vs",
					language: "yaml",
				};
			});
	}

	openUpdateNameDialog() {
		this.nameUpdateDialog = {
			form: this.fb.group({
				name: this.fb.control(this.confluence$.getValue()?.name ?? "", [
					Validators.required,
				]),
			}),
		};
	}

	acceptUpdateNameDialog() {
		const form = this.nameUpdateDialog?.form;
		if (!this.nameUpdateDialog || !form) {
			return;
		}
		form.markAllAsTouched();
		if (!form.valid) {
			return;
		}
		this.overlayService
			.withSuspense(
				this.confluence$.pipe(
					take(1),
					filter((c): c is ConfluenceDto => !!c),
					switchMap((c) =>
						this.confluenceService.updateConfluence(c.id, {
							name: form.value.name ?? undefined,
						}),
					),
					takeUntilDestroyed(this.destoryRef),
				),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Saved successfully",
				});
			});
	}

	cancelUpdateNameDialog() {
		this.nameUpdateDialog = undefined;
	}

	saveTmpl() {
		this.overlayService
			.withSuspense(
				this.confluence$.pipe(
					take(1),
					filter((c): c is ConfluenceDto => !!c),
					switchMap((c) =>
						this.confluenceService.updateConfluence(c.id, {
							template: this.tmpl,
						}),
					),
					takeUntilDestroyed(this.destoryRef),
				),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Saved successfully",
				});
			});
	}

	resetTmpl() {
		this.tmpl = this.confluence$.getValue()?.template ?? "";
		this.overlayService.toast({
			severity: "success",
			summary: "Success",
			detail: "Reset Success",
		});
	}

	openCreateSubscribeSourceDialog() {
		this.confluenceId$
			.pipe(
				tap((id) => {
					this.subscribeSourceCreation = {
						value: {
							confluence_id: id,
						},
						form: this.fb.group({
							url: ["", [Validators.required, RxwebValidators.url()]],
							name: ["", Validators.required],
							passive_sync: [false],
							proxy_server: [null as string | null],
							proxy_auth: [null as string | null],
						}),
					};
				}),
				takeUntilDestroyed(this.destoryRef),
			)
			.subscribe();
	}

	cancelCreateSubscribeSourceDialog() {
		this.subscribeSourceCreation = undefined;
	}

	acceptCreateSubscribeSourceDialog() {
		const form = this.subscribeSourceCreation?.form;
		if (!this.subscribeSourceCreation || !form) {
			return;
		}
		form.markAllAsTouched();
		if (!form.valid) {
			return;
		}
		this.overlayService
			.withSuspense(
				this.confluenceService
					.addSubscribeSource({
						...this.subscribeSourceCreation.value,
						...(form.value as RecursiveNonNullable<typeof form.value>),
					})
					.pipe(
						combineLatestWith(this.confluenceId$),
						switchMap(([_, id]) =>
							this.confluenceService.getConfluenceById(id),
						),
						takeUntilDestroyed(this.destoryRef),
					),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.subscribeSourceCreation = undefined;
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Saved successfully",
				});
			});
	}

	openUpdateSubscribeSourceDialog(item: SubscribeSourceDto) {
		this.subscribeSourceUpdate = {
			value: {
				id: item.id,
			},
			form: this.fb.group({
				url: [item.url, [Validators.required, RxwebValidators.url()]],
				name: [item.name, Validators.required],
				passive_sync: [!!item.passive_sync],
				proxy_server: [item.proxy_server],
				proxy_auth: [item.proxy_auth],
			}),
		};
	}

	cancelUpdateSubscribeSourceDialog() {
		this.subscribeSourceUpdate = undefined;
	}

	acceptUpdateSubscribeSourceContentDialog() {
		if (!this.subscribeSourceContentPreview) {
			return;
		}
		this.overlayService
			.withSuspense(
				this.confluenceService
					.updateSubscribeSource(this.subscribeSourceContentPreview.id, {
						content: this.subscribeSourceContentPreview.content,
					} as RecursiveNonNullable<SubscribeSourceUpdateDto>)
					.pipe(
						combineLatestWith(this.confluenceId$),
						switchMap(([_, id]) =>
							this.confluenceService.getConfluenceById(id),
						),
						takeUntilDestroyed(this.destoryRef),
					),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.subscribeSourceUpdate = undefined;
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Updated successfully",
				});
			});
	}

	acceptUpdateSubscribeSourceDialog() {
		const form = this.subscribeSourceUpdate?.form;
		if (!this.subscribeSourceUpdate || !form) {
			return;
		}
		form.markAllAsTouched();
		if (!form.valid) {
			return;
		}
		this.overlayService
			.withSuspense(
				this.confluenceService
					.updateSubscribeSource(
						this.subscribeSourceUpdate.value.id,
						form.value as RecursiveNonNullable<SubscribeSourceUpdateDto>,
					)
					.pipe(
						combineLatestWith(this.confluenceId$),
						switchMap(([_, id]) =>
							this.confluenceService.getConfluenceById(id),
						),
						takeUntilDestroyed(this.destoryRef),
					),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.subscribeSourceUpdate = undefined;
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Updated successfully",
				});
			});
	}

	removeSubscribeSource(id: number) {
		this.overlayService
			.withSuspense(
				this.confluenceService.removeSubscribeSource(id).pipe(
					combineLatestWith(this.confluenceId$),
					switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
					takeUntilDestroyed(this.destoryRef),
				),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.subscribeSourceCreation = undefined;
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Remove successfully",
				});
			});
	}

	syncConfluence() {
		this.overlayService
			.withSuspense(
				this.confluenceId$.pipe(
					take(1),
					switchMap((id) => this.confluenceService.syncConfluence(id)),
					takeUntilDestroyed(this.destoryRef),
				),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Sync successfully",
				});
			});
	}

	syncSubscribeSource(id: number) {
		this.overlayService
			.withSuspense(
				this.confluenceService.syncSubscribeSource(id).pipe(
					withLatestFrom(this.confluenceId$),
					switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
					takeUntilDestroyed(this.destoryRef),
				),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Sync successfully",
				});
			});
	}

	openPreviewSubscribeSourceContentDialog(item: SubscribeSourceDto) {
		this.subscribeSourceContentPreview = {
			...item,
		};
	}

	cancelPreviewSubscribeSourceContentDialog() {
		this.subscribeSourceContentPreview = undefined;
	}

	muxConfluence() {
		this.overlayService
			.withSuspense(
				this.confluenceId$.pipe(
					take(1),
					switchMap((id) => this.confluenceService.muxConfluence(id)),
					takeUntilDestroyed(this.destoryRef),
				),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Mux successfully",
				});
			});
	}

	openPreviewMuxContentDialog() {
		this.muxContentPreview = {
			content: this.confluence$.getValue()?.mux_content ?? "",
		};
	}

	cancelPreviewMuxContentDialog() {
		this.muxContentPreview = undefined;
	}

	formatTime = format;

	createProfile() {
		this.overlayService
			.withSuspense(
				this.confluenceId$.pipe(
					take(1),
					switchMap((id) =>
						this.confluenceService.addProfile({ confluence_id: id }),
					),
					combineLatestWith(this.confluenceId$),
					switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
					takeUntilDestroyed(this.destoryRef),
				),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Remove successfully",
				});
			});
	}

	removeProfile(id: number) {
		this.overlayService
			.withSuspense(
				this.confluenceService.removeProfile(id).pipe(
					combineLatestWith(this.confluenceId$),
					switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
					takeUntilDestroyed(this.destoryRef),
				),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.subscribeSourceCreation = undefined;
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Remove successfully",
				});
			});
	}

	saveCron() {
		const form = this.cronUpdateForm;
		form.markAllAsTouched();
		if (!form.valid) {
			return;
		}
		this.overlayService
			.withSuspense(
				this.confluenceId$.pipe(
					take(1),
					switchMap((id) =>
						this.confluenceService
							.updateConfluenceCron(id, {
								cron_expr: form.value.cronExpr as Exclude<
									typeof form.value.cronExpr,
									null | undefined
								>,
								cron_expr_tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
							})
							.pipe(map(() => id)),
					),
					switchMap((id) => this.confluenceService.getConfluenceById(id)),
					takeUntilDestroyed(this.destoryRef),
				),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Saved successfully",
				});
			});
	}

	saveUA() {
		const form = this.uaUpdateForm;
		form.markAllAsTouched();
		if (!form.valid) {
			return;
		}
		this.overlayService
			.withSuspense(
				this.confluenceId$.pipe(
					take(1),
					switchMap((id) =>
						this.confluenceService.updateConfluence(id, {
							user_agent: form.value.userAgent as Exclude<
								typeof form.value.userAgent,
								null | undefined
							>,
						}),
					),
					takeUntilDestroyed(this.destoryRef),
				),
			)
			.subscribe((c) => {
				this.confluence$.next(c);
				this.overlayService.toast({
					severity: "success",
					summary: "Success",
					detail: "Saved successfully",
				});
			});
	}

	async copyProfileUrl(item: ProfileDto) {
		const profileUrl = this.confluenceService.getProfileUrl(
			item.resource_token,
		);
		const qrcodeDataUrl = await this.qrcodeService.toDataURL(profileUrl);
		this.urlPreview = {
			url: profileUrl,
			qrcodeDataUrl: qrcodeDataUrl,
		};
		await this.copyUrl(profileUrl);
	}

	async copyUrl(url: string) {
		try {
			await this.clipboardService.copyText(url);
			this.overlayService.toast({
				severity: "success",
				summary: "Success",
				detail: "Copy successfully",
			});
		} catch (err: unknown) {
			this.overlayService.toast({
				severity: "error",
				summary: "Error",
				detail: (<Error>err)?.message,
			});
		}
	}

	cancelUrlPreviewDialog() {
		this.urlPreview = undefined;
	}

	pascalCase(text: string) {
		return pascalCase(text, {
			delimiter: " ",
		});
	}
}
