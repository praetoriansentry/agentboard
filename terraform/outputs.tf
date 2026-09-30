output "d1_database_id" {
  description = "Paste into wrangler.toml [[env.production.d1_databases]] database_id."
  value       = cloudflare_d1_database.board.id
}

output "hostname" {
  value = var.hostname
}

output "mtls_hostnames" {
  value = cloudflare_certificate_authorities_hostname_associations.mtls.hostnames
}
