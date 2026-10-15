# Operator public IP for the SSH allow-list (/32).
data "http" "operator_ip" {
  url = "https://checkip.amazonaws.com"
}

locals {
  operator_cidr = "${chomp(data.http.operator_ip.response_body)}/32"
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  #checkov:skip=CKV2_AWS_11:Demo VPC, flow logs not required
  cidr_block           = "10.50.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.prefix}-vpc" }
}

# Default SG: lock down (no rules) so nothing uses it by accident.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.prefix}-default-locked" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.prefix}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.50.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false # public IP assigned explicitly on the instance
  tags                    = { Name = "${var.prefix}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "${var.prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# SSH from the operator only. No inbound syslog (generator talks to the agent
# over loopback). Egress open so the agent can reach Fleet/Elasticsearch/artifacts.
resource "aws_security_group" "ingest" {
  name        = "${var.prefix}-ingest"
  description = "OT demo ingest host: SSH from operator only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from operator public IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.operator_cidr]
  }

  egress {
    description = "Outbound to Elastic Cloud, package mirrors and artifacts"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] #checkov:skip=CKV_AWS_382:Agent needs outbound HTTPS to Fleet/ES/artifacts; no NAT in this demo
  }

  tags = { Name = "${var.prefix}-ingest-sg" }
}

# ---------------------------------------------------------------------------
# GuardDuty VPC cleanup. GuardDuty Runtime Monitoring creates a managed SG,
# endpoints and ENIs not tracked in state, which block VPC deletion
# (DependencyViolation).
#
# Ordering: the instance depends_on this resource, and this resource depends on
# the VPC/SG/subnet/IGW. On destroy, Terraform therefore terminates the
# instance first (ENIs drain), then runs this provisioner, then deletes the
# subnet/IGW/VPC. Order inside: endpoints -> ENIs -> SGs (retry, never swallow).
# Destroy provisioners may only reference self.triggers.
# ---------------------------------------------------------------------------
resource "null_resource" "vpc_guardduty_cleanup" {
  triggers = {
    vpc_id  = aws_vpc.main.id
    region  = var.region
    profile = var.aws_profile
  }

  depends_on = [
    aws_vpc.main,
    aws_subnet.public,
    aws_internet_gateway.main,
    aws_route_table_association.public,
    aws_security_group.ingest,
  ]

  provisioner "local-exec" {
    when        = destroy
    interpreter = ["/bin/bash", "-c"]
    environment = {
      VPC_ID  = self.triggers.vpc_id
      REGION  = self.triggers.region
      PROFILE = self.triggers.profile
    }
    command = <<-EOT
      set -uo pipefail
      AWS="aws --profile $PROFILE --region $REGION"

      echo "[cleanup] 1/3 deleting VPC endpoints in $VPC_ID"
      EPS=$($AWS ec2 describe-vpc-endpoints --filters Name=vpc-id,Values=$VPC_ID \
        --query 'VpcEndpoints[].VpcEndpointId' --output text) || exit 1
      if [ -n "$EPS" ] && [ "$EPS" != "None" ]; then
        $AWS ec2 delete-vpc-endpoints --vpc-endpoint-ids $EPS || exit 1
        sleep 20
      fi

      echo "[cleanup] 2/3 waiting up to 3 min for ENIs to drain, deleting leftovers"
      for i in $(seq 1 18); do
        ENIS=$($AWS ec2 describe-network-interfaces --filters Name=vpc-id,Values=$VPC_ID \
          --query 'NetworkInterfaces[?Attachment==null].NetworkInterfaceId' --output text) || exit 1
        ALL=$($AWS ec2 describe-network-interfaces --filters Name=vpc-id,Values=$VPC_ID \
          --query 'length(NetworkInterfaces)' --output text) || exit 1
        for e in $ENIS; do
          [ "$e" = "None" ] && continue
          $AWS ec2 delete-network-interface --network-interface-id $e || true
        done
        [ "$ALL" = "0" ] && break
        sleep 10
      done

      echo "[cleanup] 3/3 deleting non-default security groups (retry every 30s, up to 5 min)"
      for i in $(seq 1 10); do
        SGS=$($AWS ec2 describe-security-groups --filters Name=vpc-id,Values=$VPC_ID \
          --query "SecurityGroups[?GroupName!='default'].GroupId" --output text) || exit 1
        [ -z "$SGS" ] || [ "$SGS" = "None" ] && { echo "[cleanup] no SGs left"; exit 0; }
        FAILED=0
        for sg in $SGS; do
          $AWS ec2 delete-security-group --group-id $sg || FAILED=1
        done
        [ "$FAILED" = "0" ] && { echo "[cleanup] done"; exit 0; }
        echo "[cleanup] SG delete failed (attempt $i/10), retrying in 30s"
        sleep 30
      done
      echo "[cleanup] ERROR: security groups still present after 5 min" >&2
      exit 1
    EOT
  }
}
