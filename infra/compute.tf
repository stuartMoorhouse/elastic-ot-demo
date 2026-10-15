data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-${var.instance_arch}-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "tls_private_key" "ssh" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "ssh" {
  key_name   = "${var.prefix}-key"
  public_key = tls_private_key.ssh.public_key_openssh
}

# Gitignored (*.pem) and excluded from gitleaks via .gitleaks.toml.
resource "local_sensitive_file" "ssh_private_key" {
  filename             = "${path.module}/${var.prefix}-key.pem"
  content              = tls_private_key.ssh.private_key_openssh
  file_permission      = "0600"
  directory_permission = "0700"
}

resource "aws_instance" "ingest" {
  #checkov:skip=CKV2_AWS_41:No AWS API access needed; agent talks to Elastic Cloud only
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.ingest.id]
  key_name                    = aws_key_pair.ssh.key_name
  associate_public_ip_address = true #checkov:skip=CKV_AWS_88:Public IP needed for SSH and outbound Fleet access; no NAT by design
  monitoring                  = true
  ebs_optimized               = true

  instance_market_options {
    market_type = "spot"
    spot_options {
      spot_instance_type             = "one-time"
      instance_interruption_behavior = "terminate"
    }
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/user_data.sh.tftpl", {
    stack_version    = data.ec_stack.latest.version
    agent_arch       = local.agent_arch
    fleet_url        = local.fleet_url
    enrollment_token = local.enrollment_token
  })
  user_data_replace_on_change = true

  # Terminate the instance before the GuardDuty cleanup runs on destroy.
  depends_on = [null_resource.vpc_guardduty_cleanup]

  tags = { Name = "${var.prefix}-ingest" }

}

# Ship the generator over SSH (Terraform-native). Re-runs when the file changes.
resource "terraform_data" "generator" {
  triggers_replace = [
    aws_instance.ingest.id,
    try(filesha256("${path.module}/../scripts/generator/ot_generator.py"), "missing"),
  ]

  connection {
    type        = "ssh"
    host        = aws_instance.ingest.public_ip
    user        = "ubuntu"
    private_key = tls_private_key.ssh.private_key_openssh
    timeout     = "10m"
  }

  # Wait for cloud-init (user-data) to finish before copying.
  provisioner "remote-exec" {
    inline = ["cloud-init status --wait || true", "test -d /opt/ot-demo"]
  }

  provisioner "file" {
    source      = "${path.module}/../scripts/generator/ot_generator.py"
    destination = "/opt/ot-demo/ot_generator.py"
  }

  provisioner "remote-exec" {
    inline = ["chmod 0755 /opt/ot-demo/ot_generator.py"]
  }
}
