terraform {
  required_version = ">= 1.5"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.19"
    }
  }
}

# Auth: export CLOUDFLARE_API_TOKEN (needs Zone:SSL and Certificates:Edit,
# Account:D1:Edit, and read on the zone). The provider reads it from the env.
provider "cloudflare" {}
