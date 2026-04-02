# PurpleChef — Standalone AWS Lab Environment
# Deploys Caldera server + Windows target in a new VPC

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "key_name" {
  description = "SSH key pair name (must exist in the target region)"
  type        = string
}

variable "my_ip" {
  description = "Your public IP for access control (e.g., 203.0.113.1/32)"
  type        = string
}

# --- VPC ---

resource "aws_vpc" "lab" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "purplechef-lab", Project = "PurpleChef" }
}

resource "aws_subnet" "lab" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  tags                    = { Name = "purplechef-lab-subnet", Project = "PurpleChef" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "purplechef-lab-igw", Project = "PurpleChef" }
}

resource "aws_route_table" "lab" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
  tags = { Name = "purplechef-lab-rt", Project = "PurpleChef" }
}

resource "aws_route_table_association" "lab" {
  subnet_id      = aws_subnet.lab.id
  route_table_id = aws_route_table.lab.id
}

# --- Caldera Server ---

module "caldera" {
  source        = "../../modules/caldera-server"
  vpc_id        = aws_vpc.lab.id
  subnet_id     = aws_subnet.lab.id
  key_name      = var.key_name
  allowed_cidrs = [var.my_ip]
}

# --- Windows Target ---

module "target" {
  source        = "../../modules/windows-target"
  vpc_id        = aws_vpc.lab.id
  subnet_id     = aws_subnet.lab.id
  key_name      = var.key_name
  caldera_url   = module.caldera.caldera_url
  allowed_cidrs = [var.my_ip]
}

# --- Outputs ---

output "caldera_url" {
  value = module.caldera.caldera_url
}

output "caldera_ip" {
  value = module.caldera.caldera_public_ip
}

output "target_ip" {
  value = module.target.target_public_ip
}

output "setup_instructions" {
  value = <<-EOT
    PurpleChef Lab deployed!

    1. SSH to Caldera: ssh -i ${var.key_name}.pem ubuntu@${module.caldera.caldera_public_ip}
    2. Get API key: cat /opt/caldera/.api_key
    3. Update .env:
       CHEF_CALDERA_URL=${module.caldera.caldera_url}
       CHEF_CALDERA_API_KEY=<from step 2>
    4. RDP to target: ${module.target.target_public_ip}:3389
    5. Run: chef recipe run recipes/credential-access/recipe.yml --live
  EOT
}
