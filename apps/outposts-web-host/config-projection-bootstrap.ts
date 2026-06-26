const CONFIG_PROJECTION_REALM_KEY_PREFIX = "securitydept.frontend_oidc.config_projection:v1:";

/** Build the inline script that populates Securitydept's default projection Realm. */
export function createConfigProjectionBootstrapScript(
  projections: Iterable<readonly [string, unknown]>,
): string {
  const entries = Array.from(projections);
  if (entries.length === 0) return "";

  const payload = JSON.stringify(entries);
  const realmKeyPrefix = JSON.stringify(CONFIG_PROJECTION_REALM_KEY_PREFIX);
  return `<script>for(const [clientKey,projection] of ${payload}){globalThis[Symbol.for(${realmKeyPrefix}+clientKey)]=projection;}</script>`;
}
