variable "account_id" {
  description = "Cloudflare account ID."
  type        = string
}

variable "zone_id" {
  description = "Zone ID of the domain the board is served from."
  type        = string
}

variable "hostname" {
  description = "Full hostname for the board, e.g. agentboard.example.com. Must be in the zone. Also set it in wrangler.toml [env.production] routes."
  type        = string
}

variable "d1_name" {
  description = "D1 database name. Must match database_name in wrangler.toml."
  type        = string
  default     = "agentboard"
}

variable "d1_location_hint" {
  description = "Region hint for the D1 primary (wnam, enam, weur, eeur, apac, oc)."
  type        = string
  default     = "enam"
}
