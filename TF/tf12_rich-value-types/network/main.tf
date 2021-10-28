provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "my_vpc" {
  cidr_block = var.network_config
  tags = {
    Name      = var.network_config
    yor_trace = "684f3c80-5361-42f3-9669-d0dac4074d2d"
  }
}

resource "aws_subnet" "my_subnet" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = var.network_config
  availability_zone = "us-west-2a"
  tags = {
    Name      = var.network_config
    yor_trace = "facb987a-6cbc-4863-8f1f-092d0eb80e84"
  }
}
