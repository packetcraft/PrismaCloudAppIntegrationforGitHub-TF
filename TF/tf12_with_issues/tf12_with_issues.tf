terraform {
  required_version = ">= 0.12.0"
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "foo" {
  bucket = "my-tf-log-bucket"
  acl    = "public-read-write"
  tags = {
    yor_trace = "6063a594-76c8-4792-8f19-3d74df5b2bb3"
  }
}