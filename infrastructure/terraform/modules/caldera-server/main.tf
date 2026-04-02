# PurpleChef — Caldera Server Module
# Deploys a MITRE Caldera C2 server on AWS EC2

variable "vpc_id" {
  description = "VPC ID for the Caldera server"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for the Caldera server"
  type        = string
}

variable "key_name" {
  description = "SSH key pair name"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

variable "allowed_cidrs" {
  description = "CIDR blocks allowed to access Caldera UI"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default = {
    Project = "PurpleChef"
    Component = "caldera-server"
  }
}

# --- Security Group ---

resource "aws_security_group" "caldera" {
  name_prefix = "purplechef-caldera-"
  vpc_id      = var.vpc_id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  # Caldera UI + API
  ingress {
    from_port   = 8888
    to_port     = 8888
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  # Agent callback
  ingress {
    from_port   = 7010
    to_port     = 7012
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

# --- EC2 Instance ---

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-*-22.04-amd64-server-*"]
  }
}

resource "aws_instance" "caldera" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.caldera.id]

  user_data = <<-EOF
    #!/bin/bash
    set -e
    apt-get update
    apt-get install -y git python3 python3-pip
    cd /opt
    git clone https://github.com/mitre/caldera.git --recursive --depth 1
    cd caldera
    pip3 install -r requirements.txt
    # Generate random API key
    API_KEY=$(openssl rand -hex 16)
    cat > conf/local.yml <<CONF
    port: 8888
    host: 0.0.0.0
    users:
      admin: $(openssl rand -base64 18)
    api_key_red: $API_KEY
    api_key_blue: $API_KEY
    CONF
    # WARNING: --insecure disables HTTPS. For lab use only.
    # Production deployments MUST use TLS certificates.
    nohup python3 server.py &
    echo "CALDERA_API_KEY=$API_KEY" > /opt/caldera/.api_key
  EOF

  tags = merge(var.tags, { Name = "purplechef-caldera" })
}

# --- Outputs ---

output "caldera_public_ip" {
  value = aws_instance.caldera.public_ip
}

output "caldera_url" {
  value = "http://${aws_instance.caldera.public_ip}:8888"
}

output "instance_id" {
  value = aws_instance.caldera.id
}

output "security_group_id" {
  value = aws_security_group.caldera.id
}
