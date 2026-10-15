# Keep in sync with ../terraform.tfvars.example. terraform.tfvars is gitignored.

variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "aws_profile" {
  description = "AWS CLI profile (company account 461485115270)"
  type        = string
  default     = "company"
}

variable "prefix" {
  description = "Resource name prefix"
  type        = string
  default     = "elastic-demo"
}

variable "stack_version_regex" {
  description = "Regex resolving the Elastic Stack version via data.ec_stack (default: latest 9.5.x)"
  type        = string
  default     = "9\\.5\\.\\d+"
}

variable "ec_region" {
  description = "Elastic Cloud region"
  type        = string
  default     = "eu-west-1"
}

variable "ec_deployment_template_id" {
  description = "Elastic Cloud deployment template"
  type        = string
  default     = "aws-storage-optimized"
}

variable "es_size" {
  description = "Elasticsearch hot tier size per node"
  type        = string
  default     = "2g"
}

variable "kibana_size" {
  description = "Kibana size"
  type        = string
  default     = "16g"
}

variable "integrations_server_size" {
  description = "Integrations server (Fleet) size"
  type        = string
  default     = "1g"
}

variable "instance_type" {
  description = "EC2 spot instance type (must match instance_arch)"
  type        = string
  default     = "t4g.small"
}

variable "instance_arch" {
  description = "AMI architecture: arm64 (t4g) or amd64 (t3)"
  type        = string
  default     = "arm64"
  validation {
    condition     = contains(["arm64", "amd64"], var.instance_arch)
    error_message = "instance_arch must be arm64 or amd64."
  }
}

variable "aws_tags" {
  description = "Default tags applied to all AWS resources (organisation-mandated)"
  type        = map(string)
  default     = {}
}
