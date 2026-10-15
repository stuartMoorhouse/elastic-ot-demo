# Scripts read these via `terraform -chdir=infra output -json` and write
# shared/env.json (elasticsearch_url, kibana_url, api_key, etc.).

output "elasticsearch_url" {
  value = ec_deployment.main.elasticsearch.https_endpoint
}

output "kibana_url" {
  value = ec_deployment.main.kibana.https_endpoint
}

output "fleet_url" {
  value = local.fleet_url
}

output "elastic_username" {
  value = ec_deployment.main.elasticsearch_username
}

output "elastic_password" {
  value     = ec_deployment.main.elasticsearch_password
  sensitive = true
}

output "enrollment_token" {
  value     = local.enrollment_token
  sensitive = true
}

output "agent_policy_name" {
  value = elasticstack_fleet_agent_policy.ot_demo.name
}

output "deployment_id" {
  value = ec_deployment.main.id
}

output "stack_version" {
  value = data.ec_stack.latest.version
}

output "ec2_public_ip" {
  value = aws_instance.ingest.public_ip
}

output "ssh_command" {
  value = "ssh -i ${local_sensitive_file.ssh_private_key.filename} ubuntu@${aws_instance.ingest.public_ip}"
}
