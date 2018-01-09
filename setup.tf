# CONFIGURATION AND PARAMETERS

variable "aws" {
  description = "Enter the aws profile to deploy."
}

variable "keybase" {
  description = "Enter the keybase profile to encrypt the secret_key (to decrypt: terraform output secret_key | base64 --decode | keybase pgp decrypt)"
}

variable "region" {
  default = "eu-west-1"
}

provider "aws" {
  profile    = "${var.aws}"
  region     = "${var.region}"
}

data "aws_caller_identity" "current" {}

# RESOURCES

resource "aws_iam_user" "instruqt" {
  name = "instruqt"
}

resource "aws_iam_access_key" "instruqt" {
  user = "${aws_iam_user.instruqt.name}"
  pgp_key = "keybase:${var.keybase}"
}

resource "aws_iam_user_policy" "instruqt_assume_role" {
  name = "test"
  user = "${aws_iam_user.instruqt.name}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "sts:Assume*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role" "S3AccessRole" {
  name = "InstruqtS3Access"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "S3AccessPolicy" {
  name = "InstruqtS3AccessPolicy"
  role = "${aws_iam_role.S3AccessRole.id}"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

# OUTPUT

output "role_arn" {
  value = "${aws_iam_role.S3AccessRole.arn}"
}
output "access_key" {
  value = "${aws_iam_access_key.instruqt.id}"
}
output "secret_key" {
  value = "${aws_iam_access_key.instruqt.encrypted_secret}"
}