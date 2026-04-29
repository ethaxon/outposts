import { Component, computed, DestroyRef, inject, type OnInit } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormBuilder, type FormControl, type FormGroup, Validators } from "@angular/forms";
import { ActivatedRoute } from "@angular/router";
import { RxwebValidators } from "@rxweb/reactive-form-validators";
import { format } from "date-fns";
import { isEqual } from "es-toolkit";
import type { editor as MonacoEditor } from "monaco-editor";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
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
import { AppI18nService } from "@/core/servces/app-i18n.service";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import { WINDOW } from "@/core/providers/window";
import { ClipboardService } from "@/tools/clipboard/clipboard.service";
import { QrcodeService } from "@/tools/qrcode/qrcode.service";
import type { RecursiveNonNullable } from "@/tools/type-assert";
import type { ConfluenceDto } from "../bindings/ConfluenceDto";
import type { ProfileDto } from "../bindings/ProfileDto";
import type { SubscribeSourceDto } from "../bindings/SubscribeSourceDto";
import type { SubscribeSourceUpdateDto } from "../bindings/SubscribeSourceUpdateDto";
import type { ProxyServerNameserverPolicySource } from "../bindings/ProxyServerNameserverPolicySource";
import { ConfluenceService } from "../confluence.service";
import { hourPlusLevelCronExprValidator } from "../validators/cron-expr.validators";

const DEFAULT_PROFILE_TRANSFORM_SCRIPT = `export default function transform(ctx: ProfileTransformContext): ClashMetaConfig {
  return ctx.profile;
}
`;

type ProfileTransformHeaders = Record<string, string>;

type ProfileTransformRequest = {
  headers: ProfileTransformHeaders;
  url: string;
  body: string;
};

@Component({
  standalone: false,
  selector: "app-confluence-workspace",
  templateUrl: "./workspace.component.html",
  styleUrl: "./workspace.component.scss",
})
export class WorkspaceComponent implements OnInit {
  protected readonly confluenceService = inject(ConfluenceService);
  protected readonly route = inject(ActivatedRoute);
  protected readonly appConfigService = inject(AppConfigService);
  protected readonly i18nService = inject(AppI18nService);
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
  protected readonly window = inject(WINDOW);

  confluence$ = new BehaviorSubject<ConfluenceDto | undefined>(undefined);
  confluenceName$ = this.confluence$.pipe(map((c) => `${c?.name ?? ""}`.toLocaleUpperCase()));
  protected tmplEditorOptions: MonacoEditor.IStandaloneEditorConstructionOptions = {
    theme: this.appConfigService.theme() === "dark" ? "vs-dark" : "vs",
    language: "yaml",
    automaticLayout: true,
    tabSize: 2,
    insertSpaces: true,
  };
  protected profileScriptEditorOptions: MonacoEditor.IStandaloneEditorConstructionOptions = {
    theme: this.appConfigService.theme() === "dark" ? "vs-dark" : "vs",
    language: "typescript",
    automaticLayout: true,
    tabSize: 2,
    insertSpaces: true,
    minimap: { enabled: false },
    padding: { top: 12, bottom: 12 },
  };
  protected profileTransformHeadersEditorOptions: MonacoEditor.IStandaloneEditorConstructionOptions =
    {
      theme: this.appConfigService.theme() === "dark" ? "vs-dark" : "vs",
      language: "json",
      automaticLayout: true,
      tabSize: 2,
      insertSpaces: true,
      minimap: { enabled: false },
      padding: { top: 10, bottom: 10 },
      wordWrap: "on",
    };
  protected profileTransformResultEditorOptions: MonacoEditor.IStandaloneEditorConstructionOptions =
    {
      theme: this.appConfigService.theme() === "dark" ? "vs-dark" : "vs",
      language: "yaml",
      automaticLayout: true,
      tabSize: 2,
      insertSpaces: true,
      readOnly: true,
      minimap: { enabled: false },
      padding: { top: 10, bottom: 10 },
    };
  tmpl = "";
  profiles: ProfileDto[] = [];
  subscribeSources: SubscribeSourceDto[] = [];
  policySourceOptions: { label: string; value: ProxyServerNameserverPolicySource }[] = [
    { label: "auto", value: "auto" },
    { label: "proxy-server-nameserver", value: "proxy_server_nameserver" },
    { label: "nameserver", value: "nameserver" },
    { label: "none", value: "none" },
  ];
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
      proxy_server_nameserver_policy_source: FormControl<ProxyServerNameserverPolicySource | null>;
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
      proxy_server_nameserver_policy_source: FormControl<ProxyServerNameserverPolicySource | null>;
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
  profileUpdate?: {
    value: {
      id: number;
    };
    transformScript: string;
  };
  profileTransformPreview?: {
    profile: ProfileDto;
    url: string;
    headersJson: string;
    resultYaml: string;
    error?: string;
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

  confluenceCrumbLabel = this.i18nService.translateSignal(
    "confluence.workspace.breadcrumb.confluence",
  );
  workspaceCrumbLabel = this.i18nService.translateSignal(
    "confluence.workspace.breadcrumb.workspace",
  );

  breadcrumb = computed(() => {
    return {
      items: [
        {
          label: this.confluenceCrumbLabel(),
          routerLink: ["/confluence"],
        },
        {
          label: this.workspaceCrumbLabel(),
        },
      ],
      home: { icon: "pi pi-home", routerLink: "/" },
    };
  });

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
      .subscribe((tmpl) => {
        this.tmpl = tmpl;
      });

    this.confluence$
      .pipe(
        map((c) => c?.subscribe_sources ?? []),
        distinctUntilChanged(isEqual),
        takeUntilDestroyed(this.destoryRef),
      )
      .subscribe((ss) => {
        this.subscribeSources = ss;
      });

    this.confluence$
      .pipe(
        map((c) => c?.profiles ?? ""),
        distinctUntilChanged(isEqual),
        takeUntilDestroyed(this.destoryRef),
      )
      .subscribe((ps) => {
        this.profiles = ps;
      });

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
          automaticLayout: true,
          tabSize: 2,
          insertSpaces: true,
        };
        this.profileScriptEditorOptions = {
          theme: theme === "dark" ? "vs-dark" : "vs",
          language: "typescript",
          automaticLayout: true,
          tabSize: 2,
          insertSpaces: true,
          minimap: { enabled: false },
          padding: { top: 12, bottom: 12 },
        };
        this.profileTransformHeadersEditorOptions = {
          theme: theme === "dark" ? "vs-dark" : "vs",
          language: "json",
          automaticLayout: true,
          tabSize: 2,
          insertSpaces: true,
          minimap: { enabled: false },
          padding: { top: 10, bottom: 10 },
          wordWrap: "on",
        };
        this.profileTransformResultEditorOptions = {
          theme: theme === "dark" ? "vs-dark" : "vs",
          language: "yaml",
          automaticLayout: true,
          tabSize: 2,
          insertSpaces: true,
          readOnly: true,
          minimap: { enabled: false },
          padding: { top: 10, bottom: 10 },
        };
      });
  }

  openUpdateNameDialog() {
    this.nameUpdateDialog = {
      form: this.fb.group({
        name: this.fb.control(this.confluence$.getValue()?.name ?? "", [Validators.required]),
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
        ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.toastSuccess("common.toast.saved");
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
        ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.toastSuccess("common.toast.saved");
      });
  }

  resetTmpl() {
    this.tmpl = this.confluence$.getValue()?.template ?? "";
    this.toastSuccess("confluence.workspace.toasts.reset");
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
              proxy_server_nameserver_policy_source: [
                "auto" as ProxyServerNameserverPolicySource | null,
              ],
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
            switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
          ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.subscribeSourceCreation = undefined;
        this.toastSuccess("common.toast.saved");
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
        proxy_server_nameserver_policy_source: [
          item.proxy_server_nameserver_policy_source as ProxyServerNameserverPolicySource | null,
        ],
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
            switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
          ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.subscribeSourceUpdate = undefined;
        this.toastSuccess("common.toast.updated");
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
            switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
          ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.subscribeSourceUpdate = undefined;
        this.toastSuccess("common.toast.updated");
      });
  }

  removeSubscribeSource(id: number) {
    this.overlayService
      .withSuspense(
        this.confluenceService.removeSubscribeSource(id).pipe(
          combineLatestWith(this.confluenceId$),
          switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
        ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.subscribeSourceCreation = undefined;
        this.toastSuccess("common.toast.removed");
      });
  }

  syncConfluence() {
    this.overlayService
      .withSuspense(
        this.confluenceId$.pipe(
          take(1),
          switchMap((id) => this.confluenceService.syncConfluence(id)),
        ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.toastSuccess("common.toast.synced");
      });
  }

  syncSubscribeSource(id: number) {
    this.overlayService
      .withSuspense(
        this.confluenceService.syncSubscribeSource(id).pipe(
          withLatestFrom(this.confluenceId$),
          switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
        ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.toastSuccess("common.toast.synced");
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
        ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.toastSuccess("confluence.workspace.toasts.muxed");
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
          switchMap((id) => this.confluenceService.addProfile({ confluence_id: id })),
          combineLatestWith(this.confluenceId$),
          switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
        ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.toastSuccess("common.toast.created");
      });
  }

  removeProfile(id: number) {
    this.overlayService
      .withSuspense(
        this.confluenceService.removeProfile(id).pipe(
          combineLatestWith(this.confluenceId$),
          switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
        ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.subscribeSourceCreation = undefined;
        this.toastSuccess("common.toast.removed");
      });
  }

  openUpdateProfileDialog(item: ProfileDto) {
    this.profileUpdate = {
      value: {
        id: item.id,
      },
      transformScript: item.transform_script || DEFAULT_PROFILE_TRANSFORM_SCRIPT,
    };
  }

  cancelUpdateProfileDialog() {
    this.profileUpdate = undefined;
  }

  acceptUpdateProfileDialog() {
    if (!this.profileUpdate) {
      return;
    }
    this.overlayService
      .withSuspense(
        this.confluenceService
          .updateProfile(this.profileUpdate.value.id, {
            transform_script: this.profileUpdate.transformScript,
          })
          .pipe(
            combineLatestWith(this.confluenceId$),
            switchMap(([_, id]) => this.confluenceService.getConfluenceById(id)),
          ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.profileUpdate = undefined;
        this.toastSuccess("common.toast.saved");
      });
  }

  openProfileTransformPreviewDialog(item: ProfileDto) {
    this.profileTransformPreview = {
      profile: item,
      url: this.confluenceService.getProfileUrl(item.resource_token),
      headersJson: JSON.stringify(
        {
          "user-agent": this.window.navigator.userAgent,
        },
        null,
        2,
      ),
      resultYaml: "",
    };
    this.refreshProfileTransformPreview();
  }

  cancelProfileTransformPreviewDialog() {
    this.profileTransformPreview = undefined;
  }

  updateProfileTransformPreviewUrl(url: string) {
    if (!this.profileTransformPreview) {
      return;
    }
    this.profileTransformPreview.url = url;
    this.refreshProfileTransformPreview();
  }

  updateProfileTransformPreviewHeaders(headersJson: string) {
    if (!this.profileTransformPreview) {
      return;
    }
    this.profileTransformPreview.headersJson = headersJson;
    this.refreshProfileTransformPreview();
  }

  refreshProfileTransformPreview() {
    const preview = this.profileTransformPreview;
    const confluence = this.confluence$.getValue();
    if (!preview || !confluence) {
      return;
    }

    try {
      const script = preview.profile.transform_script_transpiled?.trim();
      if (!script) {
        preview.resultYaml = confluence.mux_content;
        preview.error = this.i18nService.translate(
          "confluence.workspace.profileTransformPreview.noTranspiledScript",
        );
        return;
      }

      const request: ProfileTransformRequest = {
        headers: this.parseProfileTransformHeaders(preview.headersJson),
        url: preview.url,
        body: "",
      };
      preview.resultYaml = this.runProfileTransformScript(script, confluence.mux_content, request);
      preview.error = undefined;
    } catch (err: unknown) {
      preview.resultYaml = confluence.mux_content;
      preview.error = err instanceof Error ? err.message : `${err}`;
    }
  }

  private parseProfileTransformHeaders(headersJson: string): ProfileTransformHeaders {
    const headers = JSON.parse(headersJson || "{}") as unknown;
    if (!headers || Array.isArray(headers) || typeof headers !== "object") {
      throw new Error(
        this.i18nService.translate(
          "confluence.workspace.profileTransformPreview.headersObjectOnly",
        ),
      );
    }

    return Object.fromEntries(
      Object.entries(headers).map(([name, value]) => [name.toLowerCase(), `${value ?? ""}`]),
    );
  }

  private runProfileTransformScript(
    script: string,
    profileYaml: string,
    request: ProfileTransformRequest,
  ) {
    const profile = parseYaml(profileYaml || "{}") ?? {};
    const context = { request, profile };
    const execute = new Function(
      "__ctx",
      `
        var __exports = {};
        ${script}
        var __fn = __exports.default;
        if (typeof __fn !== "function") {
          throw new Error("No default export function found in the profile transform script");
        }
        var __result = __fn(__ctx);
        if (__result && typeof __result.then === "function") {
          throw new Error("Async profile transform scripts are not supported");
        }
        return __result === undefined ? __ctx.profile : __result;
      `,
    ) as (profileContext: unknown) => unknown;

    return stringifyYaml(execute(context));
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
        ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.toastSuccess("common.toast.saved");
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
        ),
      )
      .subscribe((c) => {
        this.confluence$.next(c);
        this.toastSuccess("common.toast.saved");
      });
  }

  async copyProfileUrl(item: ProfileDto) {
    const profileUrl = this.confluenceService.getProfileUrl(item.resource_token);
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
      this.toastSuccess("common.toast.copied");
    } catch (err: unknown) {
      this.toastError((<Error>err)?.message);
    }
  }

  cancelUrlPreviewDialog() {
    this.urlPreview = undefined;
  }

  private toastSuccess(detailKey: string) {
    this.overlayService.toast({
      severity: "success",
      summary: this.i18nService.translate("common.toast.success"),
      detail: this.i18nService.translate(detailKey),
    });
  }

  private toastError(detail?: string) {
    this.overlayService.toast({
      severity: "error",
      summary: this.i18nService.translate("common.toast.error"),
      detail,
    });
  }
}
