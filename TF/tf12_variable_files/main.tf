terraform {
  required_version = ">= 0.12.0"
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "my_vpc" {
  cidr_block = "172.16.0.0/16"
  tags = {
    Name      = "tf-0.12-for-example"
    yor_trace = "21682491-2f18-4c04-b141-ebf4a44cce93"
  }
}

resource "aws_s3_bucket" "publics3" {
  // AWS S3 buckets are accessible to public
  acl    = var.acl_file
  bucket = "publics3"
  versioning {
    enabled = true
  }
  tags = {
    yor_trace = "d9748b25-56c5-4836-aefb-7bf21324b54a"
  }
}

resource "aws_security_group" "allow_tcp" {
  name        = "allow_tcp"
  description = "Allow TCP inbound traffic"
  vpc_id      = aws_vpc.my_vpc.id
  ingress {
    description = "TCP from VPC"
    // AWS Security Groups allow internet traffic to SSH port (22)
    from_port = 99
    to_port   = 99
    protocol  = "tcp"
    cidr_blocks = [
    var.cidr_file]
  }
  tags = {
    yor_trace = "b2fb8eac-ea24-4c29-b9fb-03e257b481e5"
  }
}

resource "aws_subnet" "my_subnet" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = "172.16.10.0/24"
  availability_zone = "us-east-1a"
  tags = {
    Name      = "tf-0.12-for-example"
    yor_trace = "00df6ada-b2f0-46f0-b227-57d29c929603"
  }
}

resource "aws_instance" "ubuntu" {
  count                       = 3
  ami                         = "ami-2e1ef954"
  instance_type               = "t2.micro"
  associate_public_ip_address = (count.index == 1 ? true : false)
  subnet_id                   = aws_subnet.my_subnet.id
  tags = {
    Name      = format("terraform-0.12-for-demo-%d", count.index)
    yor_trace = "81a40a8b-6c22-4851-893f-9133caef8c71"
  }
}

# This uses the old splat expression
output "private_addresses_old" {
  value = aws_instance.ubuntu.*.private_dns
}

# This uses the new full splat operator (*)
# But this does not work in 0.12 alpha-1 or alpha-2
/*output "private_addresses_full_splat" {
  value = [ aws_instance.ubuntu[*].private_dns ]
}*/

# This uses the new for expression
output "private_addresses_new" {
  value = [
    for instance in aws_instance.ubuntu :
    instance.private_dns
  ]
}

# This uses the new conditional operator
# that can work with lists
# It should work with lists in [x, y, z] form, but does not yet do that
output "ips" {
  value = [
    for instance in aws_instance.ubuntu :
    (instance.public_ip != "" ? list(instance.private_ip, instance.public_ip) : list(instance.private_ip))
  ]
}
