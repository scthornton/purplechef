# PurpleChef — Windows Target Module
# Deploys a Windows Server EC2 instance with WinRM and optional agent bootstrapping

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID"
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

variable "caldera_url" {
  description = "Caldera server URL for agent bootstrap"
  type        = string
  default     = ""
}

variable "allowed_cidrs" {
  description = "CIDR blocks allowed to access the target"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default = {
    Project   = "PurpleChef"
    Component = "windows-target"
  }
}

# --- Security Group ---

resource "aws_security_group" "target" {
  name_prefix = "purplechef-target-"
  vpc_id      = var.vpc_id

  # RDP
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  # WinRM HTTP
  ingress {
    from_port   = 5985
    to_port     = 5985
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  # WinRM HTTPS
  ingress {
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
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

data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }
}

resource "aws_instance" "target" {
  ami                    = data.aws_ami.windows.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.target.id]

  user_data = <<-EOF
    <powershell>
    # Enable WinRM over HTTPS (preferred) with self-signed cert for lab use.
    # WARNING: Basic+Unencrypted is insecure. Production MUST use HTTPS+Kerberos.
    Enable-PSRemoting -Force
    $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
    New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
    Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true

    # Install Atomic Red Team
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
    Install-AtomicRedTeam -getAtomics -Force

    # Install Caldera agent if URL provided
    $CalderaUrl = "${var.caldera_url}"
    if ($CalderaUrl -ne "") {
      $wc = New-Object System.Net.WebClient
      $wc.Headers.add("platform","windows")
      $wc.Headers.add("file","sandcat.go")
      $data = $wc.DownloadData("$CalderaUrl/file/download")
      [IO.File]::WriteAllBytes("C:\Users\Public\sandcat.exe", $data)
      Start-Process -FilePath C:\Users\Public\sandcat.exe `
        -ArgumentList "-server $CalderaUrl -group chef-targets" -WindowStyle Hidden
    }

    # Install Sysmon for telemetry
    $SysmonUrl = "https://live.sysinternals.com/Sysmon64.exe"
    Invoke-WebRequest -Uri $SysmonUrl -OutFile C:\Windows\Temp\Sysmon64.exe
    C:\Windows\Temp\Sysmon64.exe -accepteula -i
    </powershell>
  EOF

  tags = merge(var.tags, { Name = "purplechef-target" })
}

# --- Outputs ---

output "target_public_ip" {
  value = aws_instance.target.public_ip
}

output "target_private_ip" {
  value = aws_instance.target.private_ip
}

output "instance_id" {
  value = aws_instance.target.id
}

output "security_group_id" {
  value = aws_security_group.target.id
}
