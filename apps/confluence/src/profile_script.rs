use axum::body::Bytes;
use axum::http::{HeaderMap, Uri};
use boa_engine::{Context, Source};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use swc_core::{
    common::{FileName, GLOBALS, Globals, Mark, SourceMap, sync::Lrc},
    ecma::{
        ast::Program,
        codegen::{Config as CodegenConfig, Emitter, text_writer::JsWriter},
        parser::{Parser, StringInput, Syntax, TsSyntax},
        transforms::{base::resolver, typescript::strip},
    },
};

use crate::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileScriptRequest {
    pub headers: HashMap<String, String>,
    pub url: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileScriptContext {
    pub request: ProfileScriptRequest,
    pub profile: Value,
}

pub fn build_profile_script_request(
    headers: &HeaderMap,
    uri: &Uri,
    body: &Bytes,
) -> ProfileScriptRequest {
    let url = request_url(headers, uri);
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect();

    ProfileScriptRequest {
        headers,
        url,
        body: String::from_utf8_lossy(body).into_owned(),
    }
}

fn request_url(headers: &HeaderMap, uri: &Uri) -> String {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|value| value.to_str().ok());
    let Some(host) = host else {
        return uri.to_string();
    };

    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("http");

    format!("{proto}://{host}{uri}")
}

pub fn apply_profile_transform_script(
    source: &str,
    mux_content: &str,
    request: ProfileScriptRequest,
) -> Result<String, AppError> {
    let Some(boa_compat_source) = compile_profile_transform_script(source)? else {
        return Ok(mux_content.to_string());
    };

    apply_profile_transform_script_transpiled(&boa_compat_source, mux_content, request)
}

pub fn apply_profile_transform_script_transpiled(
    source: &str,
    mux_content: &str,
    request: ProfileScriptRequest,
) -> Result<String, AppError> {
    if source.trim().is_empty() {
        return Ok(mux_content.to_string());
    }
    let profile =
        serde_yaml::from_str::<Value>(mux_content).map_err(crate::error::ConfigError::from)?;
    let context = ProfileScriptContext { request, profile };
    let context_json = serde_json::to_string(&context).map_err(|err| {
        AppError::internal_str(format!("failed to serialize profile script context: {err}"))
    })?;

    let wrapper = format!(
        r#"
        var __ctx = {context_json};
        var __exports = {{}};

        {script}

        var __fn = __exports.default;
        if (typeof __fn !== 'function') {{
            throw new Error('No default export function found in the profile transform script');
        }}
        var __result = __fn(__ctx);
        if (__result && typeof __result.then === 'function') {{
            throw new Error('Async profile transform scripts are not supported');
        }}
        JSON.stringify(__result === undefined ? __ctx.profile : __result);
        "#,
        context_json = context_json,
        script = source,
    );

    let mut context = Context::default();
    let result = context.eval(Source::from_bytes(&wrapper)).map_err(|err| {
        AppError::internal_str(format!("profile transform script execution error: {err}"))
    })?;
    let result_str = result.as_string().ok_or_else(|| {
        AppError::internal_str("profile transform script did not return a string")
    })?;
    let transformed_profile = serde_json::from_str::<Value>(&result_str.to_std_string_escaped())
        .map_err(|err| {
            AppError::internal_str(format!(
                "failed to parse profile transform script result: {err}"
            ))
        })?;

    serde_yaml::to_string(&transformed_profile)
        .map_err(crate::error::ConfigError::from)
        .map_err(AppError::from)
}

pub fn compile_profile_transform_script(source: &str) -> Result<Option<String>, AppError> {
    if source.trim().is_empty() {
        return Ok(None);
    }

    let javascript = transpile_profile_script_typescript_to_javascript(source)?;

    Ok(Some(transform_script_to_boa_compat(&javascript)))
}

pub fn transform_script_to_boa_compat(source: &str) -> String {
    source
        .replace(
            "export default async function",
            "__exports.default = async function",
        )
        .replace("export default function", "__exports.default = function")
        .replace("export default", "__exports.default =")
}

pub fn transpile_profile_script_typescript_to_javascript(source: &str) -> Result<String, AppError> {
    let cm: Lrc<SourceMap> = Default::default();
    let fm = cm.new_source_file(
        FileName::Custom("profile-transform.ts".to_string()).into(),
        source.to_string(),
    );

    GLOBALS.set(&Globals::new(), || {
        let mut parser = Parser::new(
            Syntax::Typescript(TsSyntax {
                tsx: false,
                decorators: true,
                dts: false,
                no_early_errors: true,
                disallow_ambiguous_jsx_like: true,
            }),
            StringInput::from(&*fm),
            None,
        );
        let mut module = parser.parse_module().map_err(|err| {
            AppError::internal_str(format!(
                "TypeScript parse failed for profile transform script: {err:?}"
            ))
        })?;

        if let Some(err) = parser.take_errors().into_iter().next() {
            return Err(AppError::internal_str(format!(
                "TypeScript parse failed for profile transform script: {err:?}"
            )));
        }

        let unresolved_mark = Mark::new();
        let top_level_mark = Mark::new();
        let program = Program::Module(module)
            .apply(&mut resolver(unresolved_mark, top_level_mark, false))
            .apply(&mut strip(unresolved_mark, top_level_mark));
        module = match program {
            Program::Module(module) => module,
            Program::Script(_) => unreachable!("TypeScript parser returned script program"),
        };

        let mut out = Vec::new();
        {
            let mut emitter = Emitter {
                cfg: CodegenConfig::default(),
                comments: None,
                cm: cm.clone(),
                wr: JsWriter::new(cm, "\n", &mut out, None),
            };

            emitter.emit_module(&module).map_err(|err| {
                AppError::internal_str(format!(
                    "TypeScript emit failed for profile transform script: {err}"
                ))
            })?;
        }

        String::from_utf8(out)
            .map_err(|err| AppError::internal_str(format!("SWC emitted non-UTF8 output: {err}")))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ProfileScriptRequest, apply_profile_transform_script,
        apply_profile_transform_script_transpiled, compile_profile_transform_script,
    };
    use serde_json::Value;
    use std::collections::HashMap;

    fn request_with_ua(user_agent: &str) -> ProfileScriptRequest {
        ProfileScriptRequest {
            headers: HashMap::from([("user-agent".to_string(), user_agent.to_string())]),
            url: "/api/profile_token/test".to_string(),
            body: String::new(),
        }
    }

    #[test]
    fn transform_removes_dns_proxy_policy_for_clashmi_user_agent() {
        let script = r#"
export default function transform(ctx: any): any {
  const ua = ctx.request.headers["user-agent"] ?? "";
  if (ua.includes("clashmi")) {
    if (ctx.profile.dns) {
      delete ctx.profile.dns["proxy-server-nameserver-policy"];
    }
  }
  return ctx.profile;
}
"#;
        let profile = r#"
proxies: []
proxy-groups: []
rules: []
dns:
  proxy-server-nameserver-policy:
    example.com: 1.1.1.1
  nameserver:
    - 8.8.8.8
"#;

        let output =
            apply_profile_transform_script(script, profile, request_with_ua("clashmi/1.0"))
                .unwrap();
        let output = serde_yaml::from_str::<Value>(&output).unwrap();

        assert!(
            output["dns"]
                .get("proxy-server-nameserver-policy")
                .is_none()
        );
        assert_eq!(output["dns"]["nameserver"][0], "8.8.8.8");
    }

    #[test]
    fn compiled_transform_script_can_be_reused_without_transpiling() {
        let script = r#"
export default function transform(ctx: any): any {
  ctx.profile.rules = ["MATCH,DIRECT"];
  return ctx.profile;
}
"#;
        let profile = r#"
proxies: []
proxy-groups: []
rules: []
"#;
        let transpiled = compile_profile_transform_script(script).unwrap().unwrap();

        let output = apply_profile_transform_script_transpiled(
            &transpiled,
            profile,
            request_with_ua("clashmi/1.0"),
        )
        .unwrap();
        let output = serde_yaml::from_str::<Value>(&output).unwrap();

        assert_eq!(output["rules"][0], "MATCH,DIRECT");
    }

    #[test]
    fn transform_removes_mieru_proxies_and_group_references_for_slash_user_agent() {
        let script = r#"
export default function transform(ctx: any): any {
  const ua = ctx.request.headers["user-agent"] ?? "";
  if (ua.includes("slash")) {
    const profile = ctx.profile;
    const removed = profile.proxies
      .filter((proxy: any) => proxy.type === "mieru")
      .map((proxy: any) => proxy.name);
    profile.proxies = profile.proxies.filter((proxy: any) => proxy.type !== "mieru");
    for (const group of profile["proxy-groups"]) {
      group.proxies = group.proxies.filter((name: string) => !removed.includes(name));
    }
  }
  return ctx.profile;
}
"#;
        let profile = r#"
proxies:
  - name: keep
    type: ss
    server: keep.example
  - name: drop
    type: mieru
    server: drop.example
proxy-groups:
  - name: auto
    type: select
    proxies:
      - keep
      - drop
rules: []
"#;

        let output = apply_profile_transform_script(
            script,
            profile,
            request_with_ua("Stash/3.3.3 Clash/1.9.0"),
        )
        .unwrap();
        let output = serde_yaml::from_str::<Value>(&output).unwrap();

        assert_eq!(output["proxies"].as_array().unwrap().len(), 1);
        assert_eq!(output["proxies"][0]["name"], "keep");
        assert_eq!(
            output["proxy-groups"][0]["proxies"].as_array().unwrap(),
            &[Value::String("keep".to_string())]
        );
    }
}
