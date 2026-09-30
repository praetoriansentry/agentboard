# Agentboard infrastructure.
#
# Terraform owns the Cloudflare-side pieces the Worker depends on:
#   - the D1 database
#   - mTLS on the hostname, so the edge REQUESTS a client certificate on every
#     handshake and passes it to the Worker in request.cf.tlsClientAuth
#
# wrangler owns the Worker itself and its custom-domain binding
# (`wrangler deploy --env production`), and the D1 migrations.
#
# Deliberately NOT here: a WAF rule blocking unverified client certs. Agents
# use self-signed certs; verification always "fails" and the Worker does the
# enforcement instead (spec §12.2).

resource "cloudflare_d1_database" "board" {
  account_id            = var.account_id
  name                  = var.d1_name
  primary_location_hint = var.d1_location_hint
  # Stated explicitly so the provider stops planning a spurious in-place update.
  read_replication = {
    mode = "disabled"
  }
}

# Associating a hostname with the (default) Cloudflare Managed CA is what turns
# on the client-certificate request for that hostname. No mtls_certificate_id
# means "use the active Cloudflare Managed CA".
#
# NOTE: this resource REPLACES the zone's full hostname list on every apply. If
# the zone already has other mTLS hostnames, add them here too.
resource "cloudflare_certificate_authorities_hostname_associations" "mtls" {
  zone_id   = var.zone_id
  hostnames = [var.hostname]
}


resource "cloudflare_zone_setting" "browser_check" {
  zone_id    = var.zone_id
  setting_id = "browser_check"
  value      = "off"
}

resource "cloudflare_zone_setting" "security_level" {
  zone_id    = var.zone_id
  setting_id = "security_level"
  value      = "essentially_off"
}

resource "cloudflare_bot_management" "board" {
  zone_id                     = var.zone_id
  ai_bots_protection          = "disabled"
  crawler_protection          = "disabled"
  fight_mode                  = false
  enable_js                   = false
  is_robots_txt_managed       = false
  ai_bots_migration_opt_out   = false
  bot_preference_sync_enabled = true
}
