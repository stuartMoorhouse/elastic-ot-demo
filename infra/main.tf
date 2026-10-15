terraform {
  required_version = ">= 1.5"
  required_providers {
    aws          = { source = "hashicorp/aws", version = "~> 5.0" }
    ec           = { source = "elastic/ec", version = "~> 0.12" }
    elasticstack = { source = "elastic/elasticstack", version = "~> 0.13" }
    http         = { source = "hashicorp/http", version = "~> 3.4" }
    tls          = { source = "hashicorp/tls", version = "~> 4.0" }
    local        = { source = "hashicorp/local", version = "~> 2.5" }
    null         = { source = "hashicorp/null", version = "~> 3.2" }
  }
}

# Company AWS account 461485115270 via profile "company". Verify with
# `aws sts get-caller-identity` before apply, and beware AWS_* env vars.
provider "aws" {
  region  = var.region
  profile = var.aws_profile

  default_tags {
    tags = var.aws_tags
  }
}

# Authenticates via the EC_API_KEY environment variable.
provider "ec" {}

# Configured from the ec_deployment outputs (Kibana hosts the Fleet API).
provider "elasticstack" {
  elasticsearch {
    endpoints = [ec_deployment.main.elasticsearch.https_endpoint]
    username  = ec_deployment.main.elasticsearch_username
    password  = ec_deployment.main.elasticsearch_password
  }
  kibana {
    endpoints = [ec_deployment.main.kibana.https_endpoint]
    username  = ec_deployment.main.elasticsearch_username
    password  = ec_deployment.main.elasticsearch_password
  }
  fleet {
    endpoint = ec_deployment.main.kibana.https_endpoint
    username = ec_deployment.main.elasticsearch_username
    password = ec_deployment.main.elasticsearch_password
  }
}

# ---------------------------------------------------------------------------
# Elastic Cloud deployment
#
# The ec_deployment resource exposes no `timeouts` block (verified against the
# provider schema), so the provider's built-in wait applies. Creation takes
# 4-5 minutes. If apply times out: wait 5 minutes, run `terraform refresh`,
# then `terraform plan`. NEVER re-run `terraform apply` after a timeout without
# explicit permission (prevents duplicate clusters).
# ---------------------------------------------------------------------------
data "ec_stack" "latest" {
  version_regex = var.stack_version_regex
  region        = var.ec_region
}

resource "ec_deployment" "main" {
  name                   = "elastic-ot-demo"
  region                 = var.ec_region
  version                = data.ec_stack.latest.version
  deployment_template_id = var.ec_deployment_template_id

  elasticsearch = {
    hot = {
      size        = var.es_size
      zone_count  = 1
      autoscaling = {}
    }
  }

  kibana = {
    size       = var.kibana_size
    zone_count = 1
  }

  # Hosts Fleet Server (and APM), required for Elastic Agent enrollment.
  integrations_server = {
    size       = var.integrations_server_size
    zone_count = 1
  }

  tags = {
    project = "ot-demo"
    managed = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Fleet: agent policy + enrollment token. Integration policies (Claroty CTD,
# FortiGate, endpoint logs) are attached later by scripts/configure.sh by name.
# ---------------------------------------------------------------------------
resource "elasticstack_fleet_agent_policy" "ot_demo" {
  name            = "ot-demo-policy"
  namespace       = "default"
  description     = "OT demo ingest host policy"
  monitor_logs    = true
  monitor_metrics = false
  sys_monitoring  = false
}

data "elasticstack_fleet_enrollment_tokens" "ot_demo" {
  policy_id = elasticstack_fleet_agent_policy.ot_demo.policy_id
}

locals {
  enrollment_token = [for t in data.elasticstack_fleet_enrollment_tokens.ot_demo.tokens : t.api_key if t.active][0]
  fleet_url        = ec_deployment.main.integrations_server.endpoints.fleet
  agent_arch       = var.instance_arch == "arm64" ? "arm64" : "x86_64"
}
