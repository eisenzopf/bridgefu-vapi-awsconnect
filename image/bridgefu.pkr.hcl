packer {
  required_plugins {
    amazon = {
      version = ">= 1.3.6, < 2.0.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "bridgefu_repository" {
  type    = string
  default = "https://github.com/eisenzopf/bridgefu.git"
}

variable "bridgefu_commit" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.bridgefu_commit))
    error_message = "Bridgefu_commit must be a full Git commit SHA."
  }
}

variable "bridgefu_cargo_lock_sha256" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.bridgefu_cargo_lock_sha256))
    error_message = "Bridgefu_cargo_lock_sha256 must be a SHA-256 digest."
  }
}

variable "release_version" {
  type = string
}

source "amazon-ebs" "bridgefu_arm64" {
  region        = var.aws_region
  # Give four bounded Cargo jobs 8 GiB each for release linking. This temporary
  # build instance does not determine the customer runtime instance type.
  instance_type = "m7g.2xlarge"
  ssh_username  = "ec2-user"
  ami_name      = "bridgefu-vapi-awsconnect-${var.release_version}-${formatdate("YYYYMMDDhhmmss", timestamp())}"

  source_ami_filter {
    filters = {
      architecture        = "arm64"
      name                = "al2023-ami-2023.*-kernel-6.1-arm64"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["137112412989"]
    most_recent = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  launch_block_device_mappings {
    device_name = "/dev/xvda"
    volume_type = "gp3"
    volume_size = 24
    # Public AMIs require public, unencrypted backing snapshots. Build releases
    # in an isolated publisher account with EBS encryption-by-default disabled.
    encrypted             = false
    delete_on_termination = true
  }

  tags = {
    Name                 = "bridgefu-vapi-awsconnect-${var.release_version}"
    ManagedBy            = "bridgefu-vapi-awsconnect"
    BridgefuCommit       = var.bridgefu_commit
    BridgefuRelease      = var.release_version
    BridgefuRvoipVersion = "0.3.7"
  }
}

build {
  sources = ["source.amazon-ebs.bridgefu_arm64"]

  provisioner "shell" {
    inline = ["install -d -m 0755 /tmp/bridgefu-runtime"]
  }

  provisioner "file" {
    source      = "image/runtime/"
    destination = "/tmp/bridgefu-runtime/"
  }

  provisioner "shell" {
    script = "image/install.sh"
    environment_vars = [
      "BRIDGEFU_REPOSITORY=${var.bridgefu_repository}",
      "BRIDGEFU_COMMIT=${var.bridgefu_commit}",
      "BRIDGEFU_CARGO_LOCK_SHA256=${var.bridgefu_cargo_lock_sha256}",
      "BRIDGEFU_RELEASE_VERSION=${var.release_version}",
    ]
  }

  post-processor "manifest" {
    output     = "target/packer-manifest.json"
    strip_path = true
  }
}
