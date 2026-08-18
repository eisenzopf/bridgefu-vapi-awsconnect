packer {
  required_plugins {
    amazon = {
      version = "= 1.3.9"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "source_ami_id" {
  type = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{17}$", var.source_ami_id))
    error_message = "Source_ami_id must be an exact AMI ID."
  }
}

variable "builder_instance_type" {
  type = string
  validation {
    condition     = var.builder_instance_type == "m7g.4xlarge"
    error_message = "Builder_instance_type must use the reviewed 16-vCPU builder."
  }
}

variable "cargo_build_jobs" {
  type = number
  validation {
    condition     = var.cargo_build_jobs == 8
    error_message = "Cargo_build_jobs must use the reviewed parallelism."
  }
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

variable "candidate_id" {
  type = string
  validation {
    condition     = can(regex("^candidate-[A-Za-z0-9.-]{8,96}$", var.candidate_id))
    error_message = "Candidate_id must be the immutable candidate execution ID."
  }
}

variable "distribution_repository_commit" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.distribution_repository_commit))
    error_message = "Distribution_repository_commit must be a full Git commit SHA."
  }
}

source "amazon-ebs" "bridgefu_arm64" {
  region = var.aws_region
  # Give eight bounded Cargo jobs 8 GiB each for release linking. This temporary
  # build instance does not determine the customer runtime instance type.
  instance_type = var.builder_instance_type
  ssh_username  = "ec2-user"
  ami_name      = "bridgefu-vapi-awsconnect-${var.release_version}-${formatdate("YYYYMMDDhhmmss", timestamp())}"

  source_ami = var.source_ami_id

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
    Name                     = "bridgefu-vapi-awsconnect-${var.release_version}"
    ManagedBy                = "bridgefu-vapi-awsconnect"
    BridgefuCommit           = var.bridgefu_commit
    BridgefuCandidateId      = var.candidate_id
    BridgefuRepositoryCommit = var.distribution_repository_commit
    BridgefuRelease          = var.release_version
    BridgefuRvoipVersion     = "0.3.8"
  }

  snapshot_tags = {
    ManagedBy                = "bridgefu-vapi-awsconnect"
    BridgefuCommit           = var.bridgefu_commit
    BridgefuCandidateId      = var.candidate_id
    BridgefuRepositoryCommit = var.distribution_repository_commit
    BridgefuRelease          = var.release_version
    BridgefuRvoipVersion     = "0.3.8"
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

  provisioner "file" {
    source      = "image/build-inputs.json"
    destination = "/tmp/bridgefu-build-inputs.json"
  }

  provisioner "shell" {
    script = "image/install.sh"
    environment_vars = [
      "BRIDGEFU_REPOSITORY=${var.bridgefu_repository}",
      "BRIDGEFU_COMMIT=${var.bridgefu_commit}",
      "BRIDGEFU_CARGO_LOCK_SHA256=${var.bridgefu_cargo_lock_sha256}",
      "BRIDGEFU_RELEASE_VERSION=${var.release_version}",
      "BRIDGEFU_SOURCE_AMI_ID=${var.source_ami_id}",
      "BRIDGEFU_BUILD_JOBS=${var.cargo_build_jobs}",
    ]
  }

  post-processor "manifest" {
    output     = "target/packer-manifest.json"
    strip_path = true
  }
}
