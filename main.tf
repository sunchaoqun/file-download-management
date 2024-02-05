variable "region" {}
variable "file_download_bucket_name" {}
variable "global_salt" {}
variable "cognito_user_pool_name" {}
variable "cognito_user_pool_registration_name" {}
variable "generate_alb_vpc_id" {}
variable "generate_alb_subnet_ids" {}


provider "aws" {
  region = var.region # 您可以更改为您的区域
}

provider "aws" {
  region = "us-east-1" 
  alias  = "us-east-1"
}

# 数据源，用于获取 AWS 账户ID
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "s3_download_checker_role" {
  name = "s3_download_checker_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = ["lambda.amazonaws.com","edgelambda.amazonaws.com"]
        },
      },
    ],
  })
}

resource "aws_iam_policy" "s3_download_checker_policy" {
  name        = "s3_download_checker_policy"
  description = "A policy that allows lambda to update Cognito user attributes"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
          "Effect": "Allow",
          "Action": [
              "logs:CreateLogGroup",
              "logs:CreateLogStream",
              "logs:PutLogEvents"
          ],
          "Resource": [
              "arn:aws:logs:*:*:*"
          ]
      },
      {
          "Effect": "Allow",
          "Action": [
              "cognito-idp:AdminGetUser",
              "cognito-idp:AdminUpdateUserAttributes"
          ],
          "Resource": [
              "arn:aws:cognito-idp:${var.region}:${data.aws_caller_identity.current.account_id}:userpool/${aws_cognito_user_pool.file_download_management_pool.id}"
          ]
      }
    ],
  })
}

resource "aws_iam_role_policy_attachment" "lambda_s3_download_checker_attach" {
  role       = aws_iam_role.s3_download_checker_role.name
  policy_arn = aws_iam_policy.s3_download_checker_policy.arn
}

data "archive_file" "s3_download_checker" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_source/s3_download_checker/"
  output_path = "${path.module}/s3_download_checker.zip"
}

resource "aws_lambda_function" "s3_download_checker" {
  depends_on    = [null_resource.modify_lambda_edge]
  provider      = aws.us-east-1
  filename      = data.archive_file.s3_download_checker.output_path
  function_name = "s3_download_checker"
  role          = aws_iam_role.s3_download_checker_role.arn
  handler       = "index.handler"
  runtime       = "nodejs14.x"
  publish       = true
  timeout       = 10
  source_code_hash = data.archive_file.s3_download_checker.output_base64sha256
}

resource "aws_lambda_alias" "s3_download_checker_alias" {
  provider         = aws.us-east-1
  depends_on       = [aws_lambda_function.s3_download_checker]
  name             = "s3-download-checker-alias"
  description      = "An alias to the latest version"
  function_name    = aws_lambda_function.s3_download_checker.function_name
  function_version = "$LATEST"
}

# 创建 S3 存储桶
resource "aws_s3_bucket" "file_download_bucket" {
  bucket = var.file_download_bucket_name # 确保这是一个全球唯一的名字
}

# 创建 CloudFront OAI (Origin Access Identity)
resource "aws_cloudfront_origin_access_identity" "oai" {
  comment = "OAI for ${aws_s3_bucket.file_download_bucket.id}"
}

resource "aws_s3_object" "index_html" {
  depends_on   = [null_resource.modify_index_html]
  bucket       = aws_s3_bucket.file_download_bucket.bucket
  key          = "index.html"
  source       = "${path.module}/index.html"
  content_type = "text/html" # 设置 Content-Type
  acl          = "private"
}

resource "aws_s3_object" "register_html" {
  depends_on   = [null_resource.modify_register_html]
  bucket       = aws_s3_bucket.file_download_bucket.bucket
  key          = "register.html"
  source       = "${path.module}/register.html"
  content_type = "text/html" # 设置 Content-Type
  acl          = "private"
}

# 创建 CloudFront 分发
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.file_download_bucket.bucket_domain_name
    origin_id   = "S3-Origin"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.oai.cloudfront_access_identity_path
    }
  }

  # 添加 restrictions 块
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # 添加 viewer_certificate 块
  viewer_certificate {
    cloudfront_default_certificate = true
  }

  enabled = true

  # 默认行为
  default_cache_behavior {

    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-Origin"

    viewer_protocol_policy = "https-only"

    # 使用 CachingOptimized 缓存策略
    cache_policy_id = "658327ea-f89d-4fab-a63d-7e88639e58f6"
  }

  # Lambda 函数关联的行为
  ordered_cache_behavior {
    path_pattern     = "/files/*" # 定义路径模式
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-Origin"

    viewer_protocol_policy = "https-only"

    forwarded_values {
      query_string = false
      headers      = ["Origin", "Access-Control-Request-Headers", "Access-Control-Request-Method"]
      cookies {
        forward = "all"
      }
    }

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = "${aws_lambda_function.s3_download_checker.arn}:${aws_lambda_function.s3_download_checker.version}" 
      include_body = false
    }

    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
  }
}

# 更新 S3 存储桶策略
resource "aws_s3_bucket_policy" "file_download_bucket_policy" {
  bucket = aws_s3_bucket.file_download_bucket.id
  # 使存储桶仅通过 CloudFront 访问
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity ${aws_cloudfront_origin_access_identity.oai.id}"
        },
        Action   = "s3:GetObject",
        Resource = "${aws_s3_bucket.file_download_bucket.arn}/*"
      }
    ]
  })
}

data "archive_file" "s3_download_management_api_generate_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_source/s3_download_management_api_generate_lambda/"
  output_path = "${path.module}/s3_download_management_api_generate_lambda.zip"
}

resource "aws_lambda_function" "s3_download_management_api_generate_lambda" {
  filename         = data.archive_file.s3_download_management_api_generate_lambda.output_path
  function_name    = "s3_download_management_api_generate_lambda"
  role             = aws_iam_role.s3_download_management_api_generate_lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.10"
  source_code_hash = data.archive_file.s3_download_management_api_generate_lambda.output_base64sha256
  timeout          = 20
  memory_size      = 512
  environment {
    variables = {
      USER_POOL_ID            = aws_cognito_user_pool.file_download_management_pool.id
      PUBLIC_KEY_USER_POOL_ID = aws_cognito_user_pool.public_key_registration_pool.id
      CLIENT_ID               = aws_cognito_user_pool_client.file_download_management_client.id
      SALT                    = var.global_salt
      BASE_PATH               = "files"
      FILE_BASE_URL= "https://${aws_cloudfront_distribution.s3_distribution.domain_name}"
      DESTINATION_REGION = "${var.region}"
      DESTINATION_BUCKET = aws_s3_bucket.file_download_bucket.bucket
      CLOUDFRONT_DOMAIN_NAME = aws_cloudfront_distribution.s3_distribution.domain_name
    }
  }
}

resource "aws_iam_role" "s3_download_management_api_generate_lambda_role" {
  name = "s3_download_management_api_generate_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
      },
    ],
  })
}

resource "aws_iam_policy" "s3_download_management_api_generate_lambda_policy" {
  name        = "s3_download_management_api_generate_lambda_policy"
  description = "A policy that allows lambda to update Cognito user attributes"

  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "SNS:Publish",
                "ses:SendEmail"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${aws_lambda_function.s3_download_management_api_generate_lambda.function_name}:*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": "cognito-idp:ListUsers",
            "Resource": [
              "arn:aws:cognito-idp:${var.region}:${data.aws_caller_identity.current.account_id}:userpool/${aws_cognito_user_pool.file_download_management_pool.id}",
              "arn:aws:cognito-idp:${var.region}:${data.aws_caller_identity.current.account_id}:userpool/${aws_cognito_user_pool.public_key_registration_pool.id}"
            ]
        }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "s3_download_management_api_generate_lambda_attach" {
  role       = aws_iam_role.s3_download_management_api_generate_lambda_role.name
  policy_arn = aws_iam_policy.s3_download_management_api_generate_lambda_policy.arn
}

resource "aws_iam_role_policy_attachment" "s3_full_access_attach" {
  role       = aws_iam_role.s3_download_management_api_generate_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

data "archive_file" "s3_download_management_api_verify_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_source/s3_download_management_api_verify_lambda/"
  output_path = "${path.module}/s3_download_management_api_verify_lambda.zip"
}

data "archive_file" "public_key_registration_api_signup_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_source/public_key_registration_api_signup_lambda/"
  output_path = "${path.module}/public_key_registration_api_signup_lambda.zip"
}

resource "aws_lambda_function" "s3_download_management_api_verify_lambda" {
  filename      = data.archive_file.s3_download_management_api_verify_lambda.output_path
  function_name = "s3_download_management_api_verify_lambda"
  role          = aws_iam_role.s3_download_management_api_verify_lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.10"
  timeout       = 10
  source_code_hash = data.archive_file.s3_download_management_api_verify_lambda.output_base64sha256
  environment {
    variables = {
      USER_POOL_ID           = aws_cognito_user_pool.file_download_management_pool.id
      CLIENT_ID              = aws_cognito_user_pool_client.file_download_management_client.id
      SALT                   = var.global_salt
      CLOUDFRONT_DOMAIN_NAME = aws_cloudfront_distribution.s3_distribution.domain_name
    }
  }
}

resource "aws_lambda_function" "public_key_registration_api_signup_lambda" {
  filename      = data.archive_file.public_key_registration_api_signup_lambda.output_path
  function_name = "public_key_registration_api_signup_lambda"
  role          = aws_iam_role.public_key_registration_api_signup_lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.10"
  timeout       = 10
  source_code_hash = data.archive_file.public_key_registration_api_signup_lambda.output_base64sha256
  environment {
    variables = {
      USER_POOL_ID           = aws_cognito_user_pool.public_key_registration_pool.id
      CLIENT_ID              = aws_cognito_user_pool_client.public_key_registration_client.id
      SALT                   = var.global_salt
      CLOUDFRONT_DOMAIN_NAME = aws_cloudfront_distribution.s3_distribution.domain_name
    }
  }
}

resource "aws_iam_role" "public_key_registration_api_signup_lambda_role" {
  name = "public_key_registration_api_signup_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
      },
    ],
  })
}

resource "aws_iam_policy" "public_key_registration_api_signup_lambda_policy" {
  name        = "public_key_registration_api_signup_lambda_policy"
  description = "A policy that allows lambda to update Cognito user attributes"

  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
          "Effect": "Allow",
          "Action": "logs:CreateLogGroup",
          "Resource": "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
          "Effect": "Allow",
          "Action": [
              "logs:CreateLogStream",
              "logs:PutLogEvents"
          ],
          "Resource": [
              "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${aws_lambda_function.public_key_registration_api_signup_lambda.function_name}:*"
          ]
      },
      {
          "Effect": "Allow",
          "Action": [
              "cognito-idp:AdminGetUser"
          ],
          "Resource": [
              "arn:aws:cognito-idp:${var.region}:${data.aws_caller_identity.current.account_id}:userpool/${aws_cognito_user_pool.public_key_registration_pool.id}"
          ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "public_key_registration_api_signup_lambda_attach" {
  role       = aws_iam_role.public_key_registration_api_signup_lambda_role.name
  policy_arn = aws_iam_policy.public_key_registration_api_signup_lambda_policy.arn
}

resource "aws_iam_role" "s3_download_management_api_verify_lambda_role" {
  name = "s3_download_management_api_verify_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
      },
    ],
  })
}

resource "aws_iam_policy" "s3_download_management_api_verify_lambda_policy" {
  name        = "s3_download_management_api_verify_lambda_policy"
  description = "A policy that allows lambda to update Cognito user attributes"

  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
          "Effect": "Allow",
          "Action": "logs:CreateLogGroup",
          "Resource": "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
          "Effect": "Allow",
          "Action": [
              "logs:CreateLogStream",
              "logs:PutLogEvents"
          ],
          "Resource": [
              "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${aws_lambda_function.s3_download_management_api_verify_lambda.function_name}:*"
          ]
      },
      {
          "Effect": "Allow",
          "Action": [
              "cognito-idp:AdminGetUser"
          ],
          "Resource": [
              "arn:aws:cognito-idp:${var.region}:${data.aws_caller_identity.current.account_id}:userpool/${aws_cognito_user_pool.file_download_management_pool.id}"
          ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "s3_download_management_api_verify_lambda_attach" {
  role       = aws_iam_role.s3_download_management_api_verify_lambda_role.name
  policy_arn = aws_iam_policy.s3_download_management_api_verify_lambda_policy.arn
}

resource "aws_api_gateway_rest_api" "s3_download_management_api" {
  name        = "S3 Download Management API"
  description = "S3 Download Management API"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_resource" "generate" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  parent_id   = aws_api_gateway_rest_api.s3_download_management_api.root_resource_id
  path_part   = "generate"
}

resource "aws_api_gateway_method" "generate_post" {
  rest_api_id   = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.generate.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_resource" "verify" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  parent_id   = aws_api_gateway_rest_api.s3_download_management_api.root_resource_id
  path_part   = "verify"
}

resource "aws_api_gateway_method" "verify_post" {
  rest_api_id   = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.verify.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_resource" "public_key_signup" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  parent_id   = aws_api_gateway_rest_api.s3_download_management_api.root_resource_id
  path_part   = "public_key_signup"
}

resource "aws_api_gateway_method" "public_key_signup_post" {
  rest_api_id   = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.public_key_signup.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "generate_lambda" {
  rest_api_id             = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id             = aws_api_gateway_resource.generate.id
  http_method             = aws_api_gateway_method.generate_post.http_method
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.s3_download_management_api_generate_lambda.invoke_arn
  integration_http_method = aws_api_gateway_method.verify_post.http_method
}

resource "aws_api_gateway_integration" "verify_lambda" {
  rest_api_id             = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id             = aws_api_gateway_resource.verify.id
  http_method             = aws_api_gateway_method.verify_post.http_method
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.s3_download_management_api_verify_lambda.invoke_arn
  integration_http_method = aws_api_gateway_method.verify_post.http_method
}

resource "aws_api_gateway_integration" "public_key_signup_lambda" {
  rest_api_id             = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id             = aws_api_gateway_resource.public_key_signup.id
  http_method             = aws_api_gateway_method.public_key_signup_post.http_method
  type                    = "AWS"
  uri                     = aws_lambda_function.public_key_registration_api_signup_lambda.invoke_arn
  integration_http_method = aws_api_gateway_method.public_key_signup_post.http_method
}

resource "aws_api_gateway_deployment" "s3_download_management_api_deployment" {
  depends_on = [
    aws_api_gateway_integration.generate_lambda,
    aws_api_gateway_integration.verify_lambda,
    aws_api_gateway_integration.public_key_signup_lambda,
  ]

  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  stage_name  = "dev"
}

resource "aws_api_gateway_integration_response" "verify_integration_response" {
  depends_on  = [aws_api_gateway_integration.verify_lambda]
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id = aws_api_gateway_resource.verify.id
  http_method = aws_api_gateway_method.verify_post.http_method
  status_code = "200"  # 您期望的 HTTP 状态码

  # response_templates 可用于转换从集成返回的数据
  response_templates = {
    "application/json" = ""
  }

  # 可以指定 response_parameters 来修改响应头
  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"       = "'https://${aws_cloudfront_distribution.s3_distribution.domain_name}'"
    "method.response.header.Access-Control-Allow-Credentials"  = "'true'"
    "method.response.header.Set-Cookie"                        = "integration.response.body.headers.Set-Cookie"
  }
}

resource "aws_api_gateway_method_response" "verify_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id = aws_api_gateway_resource.verify.id
  http_method = aws_api_gateway_method.verify_post.http_method
  status_code = "200"

  # 可以在这里定义响应模型和响应头
  response_models = {
    "application/json" = "Empty"
  }

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"                        = true
    "method.response.header.Access-Control-Allow-Credentials"                   = true
    "method.response.header.Set-Cookie"                                         = true
  }
}

resource "aws_api_gateway_integration_response" "public_key_signup_integration_response" {
  depends_on  = [aws_api_gateway_integration.public_key_signup_lambda]
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id = aws_api_gateway_resource.public_key_signup.id
  http_method = aws_api_gateway_method.public_key_signup_post.http_method
  status_code = "200"  # 您期望的 HTTP 状态码

  # response_templates 可用于转换从集成返回的数据
  response_templates = {
    "application/json" = ""
  }

  # 可以指定 response_parameters 来修改响应头
  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"       = "'https://${aws_cloudfront_distribution.s3_distribution.domain_name}'"
    "method.response.header.Access-Control-Allow-Credentials"  = "'true'"
    "method.response.header.Set-Cookie"                        = "integration.response.body.headers.Set-Cookie"
  }
}

resource "aws_api_gateway_method_response" "public_key_signup_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id = aws_api_gateway_resource.public_key_signup.id
  http_method = aws_api_gateway_method.public_key_signup_post.http_method
  status_code = "200"

  # 可以在这里定义响应模型和响应头
  response_models = {
    "application/json" = "Empty"
  }

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"                        = true
    "method.response.header.Access-Control-Allow-Credentials"                   = true
    "method.response.header.Set-Cookie"                                         = true
  }
}

resource "aws_api_gateway_method" "verify_options" {
  rest_api_id   = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.verify.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_method_response" "options_cors" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.verify.id
  http_method = aws_api_gateway_method.verify_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Credentials" = true
    "method.response.header.Access-Control-Allow-Headers"     = true
    "method.response.header.Access-Control-Allow-Methods"     = true
    "method.response.header.Access-Control-Allow-Origin"      = true
  }

  response_models = {
    "application/json" = "Empty"
  }
}

resource "aws_api_gateway_integration" "options_cors" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.verify.id
  http_method = aws_api_gateway_method.verify_options.http_method

  type                    = "MOCK"
  passthrough_behavior    = "WHEN_NO_MATCH"
  request_templates       = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_integration_response" "options_cors" {
  depends_on    = [aws_api_gateway_integration.options_cors]
  rest_api_id   = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.verify.id
  http_method   = aws_api_gateway_method.verify_options.http_method
  status_code   = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Credentials" = "'true'"
    "method.response.header.Access-Control-Allow-Headers"     = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent'"
    "method.response.header.Access-Control-Allow-Methods"     = "'POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"      = "'https://${aws_cloudfront_distribution.s3_distribution.domain_name}'"
  }
}

resource "aws_api_gateway_method" "generate_options" {
  rest_api_id   = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.generate.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_method_response" "generate_options_cors" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.generate.id
  http_method = aws_api_gateway_method.generate_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Credentials" = true
    "method.response.header.Access-Control-Allow-Headers"     = true
    "method.response.header.Access-Control-Allow-Methods"     = true
    "method.response.header.Access-Control-Allow-Origin"      = true
  }

  response_models = {
    "application/json" = "Empty"
  }
}

resource "aws_api_gateway_integration" "generate_options_cors" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.generate.id
  http_method = aws_api_gateway_method.generate_options.http_method

  type                    = "MOCK"
  passthrough_behavior    = "WHEN_NO_MATCH"
  request_templates       = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_integration_response" "generate_options_cors" {
  depends_on    = [aws_api_gateway_integration.generate_options_cors]
  rest_api_id   = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.generate.id
  http_method   = aws_api_gateway_method.generate_options.http_method
  status_code   = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Credentials" = "'true'"
    "method.response.header.Access-Control-Allow-Headers"     = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent'"
    "method.response.header.Access-Control-Allow-Methods"     = "'POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"      = "'https://${aws_cloudfront_distribution.s3_distribution.domain_name}'"
  }
}

resource "aws_api_gateway_method" "public_key_signup_options" {
  rest_api_id   = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.public_key_signup.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_method_response" "public_key_signup_options_cors" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.public_key_signup.id
  http_method = aws_api_gateway_method.public_key_signup_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Credentials" = true
    "method.response.header.Access-Control-Allow-Headers"     = true
    "method.response.header.Access-Control-Allow-Methods"     = true
    "method.response.header.Access-Control-Allow-Origin"      = true
  }

  response_models = {
    "application/json" = "Empty"
  }
}

resource "aws_api_gateway_integration" "public_key_signup_options_cors" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.public_key_signup.id
  http_method = aws_api_gateway_method.public_key_signup_options.http_method

  type                    = "MOCK"
  passthrough_behavior    = "WHEN_NO_MATCH"
  request_templates       = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_integration_response" "public_key_signup_options_cors" {
  depends_on    = [aws_api_gateway_integration.public_key_signup_options_cors]
  rest_api_id   = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id   = aws_api_gateway_resource.public_key_signup.id
  http_method   = aws_api_gateway_method.public_key_signup_options.http_method
  status_code   = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Credentials" = "'true'"
    "method.response.header.Access-Control-Allow-Headers"     = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent'"
    "method.response.header.Access-Control-Allow-Methods"     = "'POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"      = "'https://${aws_cloudfront_distribution.s3_distribution.domain_name}'"
  }
}

resource "aws_api_gateway_integration_response" "generate_integration_response" {
  depends_on  = [aws_api_gateway_integration.generate_lambda]
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id = aws_api_gateway_resource.generate.id
  http_method = aws_api_gateway_method.generate_post.http_method
  status_code = "200"  # 您期望的 HTTP 状态码

  # response_templates 可用于转换从集成返回的数据
  response_templates = {
    "application/json" = ""
  }

  # 可以指定 response_parameters 来修改响应头
  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"       = "'https://${aws_cloudfront_distribution.s3_distribution.domain_name}'"
    "method.response.header.Access-Control-Allow-Credentials"  = "'true'"
    "method.response.header.Set-Cookie"                        = "integration.response.body.headers.Set-Cookie"
  }
}

resource "aws_api_gateway_method_response" "generate_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.s3_download_management_api.id
  resource_id = aws_api_gateway_resource.generate.id
  http_method = aws_api_gateway_method.generate_post.http_method
  status_code = "200"

  # 可以在这里定义响应模型和响应头
  response_models = {
    "application/json" = "Empty"
  }

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"                        = true
    "method.response.header.Access-Control-Allow-Credentials"                   = true
    "method.response.header.Set-Cookie"                                         = true
  }
}

resource "aws_lambda_permission" "api_gateway_invoke_lambda_generate" {
  statement_id  = "AllowExecutionFromAPIGatewayGenerate"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_download_management_api_generate_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn = "${aws_api_gateway_rest_api.s3_download_management_api.execution_arn}/*/POST/generate"
}

resource "aws_lambda_permission" "api_gateway_invoke_lambda_verify" {
  statement_id  = "AllowExecutionFromAPIGatewayVerify"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_download_management_api_verify_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn = "${aws_api_gateway_rest_api.s3_download_management_api.execution_arn}/*/POST/verify"
}

resource "aws_lambda_permission" "api_gateway_invoke_lambda_public_key_signup" {
  statement_id  = "AllowExecutionFromAPIGatewayPublicKey"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.public_key_registration_api_signup_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn = "${aws_api_gateway_rest_api.s3_download_management_api.execution_arn}/*/POST/public_key_signup"
}

resource "aws_lambda_permission" "cognito_invoke_lambda_pre_sign_up" {
  statement_id  = "AllowExecutionFromCognitoPreSignUp"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pre_signup_lambda.function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn = "arn:aws:cognito-idp:${var.region}:${data.aws_caller_identity.current.account_id}:userpool/${aws_cognito_user_pool.file_download_management_pool.id}"
}

resource "aws_lambda_permission" "cognito_invoke_lambda_pre_auth" {
  statement_id  = "AllowExecutionFromCognitoPreAuth"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pre_auth_lambda.function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn = "arn:aws:cognito-idp:${var.region}:${data.aws_caller_identity.current.account_id}:userpool/${aws_cognito_user_pool.file_download_management_pool.id}"
}

resource "null_resource" "modify_index_html" {
  provisioner "local-exec" {
    command = "bash modify_index.sh ${aws_api_gateway_deployment.s3_download_management_api_deployment.invoke_url}"
  }

  # 触发器可以是任何会在您需要重新执行脚本时发生变化的值
  triggers = {
    always_run = "${timestamp()}"
  }
}

resource "null_resource" "modify_register_html" {
  provisioner "local-exec" {
    command = "bash modify_register.sh ${aws_api_gateway_deployment.s3_download_management_api_deployment.invoke_url}"
  }

  # 触发器可以是任何会在您需要重新执行脚本时发生变化的值
  triggers = {
    always_run = "${timestamp()}"
  }
}

resource "null_resource" "modify_lambda_edge" {
  provisioner "local-exec" {
    command = "bash modify_lambda_edge.sh ${var.region} ${aws_cognito_user_pool.file_download_management_pool.id}"
  }

  # 触发器可以是任何会在您需要重新执行脚本时发生变化的值
  triggers = {
    always_run = "${timestamp()}"
  }
}

data "archive_file" "pre_signup_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_source/pre_signup_lambda/"
  output_path = "${path.module}/pre_signup_lambda.zip"
}

data "archive_file" "pre_auth_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_source/pre_auth_lambda/"
  output_path = "${path.module}/pre_auth_lambda_lambda.zip"
}

resource "aws_lambda_function" "pre_signup_lambda" {
  filename      = data.archive_file.pre_signup_lambda.output_path
  function_name = "pre_signup_lambda"
  role          = aws_iam_role.pre_signup_lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.10"

  source_code_hash = data.archive_file.pre_signup_lambda.output_base64sha256

}

resource "aws_lambda_function" "pre_auth_lambda" {
  filename      = data.archive_file.pre_auth_lambda.output_path
  function_name = "pre_auth_lambda"
  role          = aws_iam_role.pre_auth_lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.10"

  source_code_hash = data.archive_file.pre_auth_lambda.output_base64sha256

}

resource "aws_iam_role" "pre_auth_lambda_role" {
  name = "pre_auth_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
      },
    ],
  })
}

resource "aws_iam_role" "pre_signup_lambda_role" {
  name = "pre_signup_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
      },
    ],
  })
}

resource "aws_iam_policy" "pre_sign_up_policy" {
  name        = "pre_sign_up_policy"
  description = "A policy that allows lambda to update Cognito user attributes"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${aws_lambda_function.pre_signup_lambda.function_name}:*"
            ]
        },
    ],
  })
}

resource "aws_iam_role_policy_attachment" "pre_sign_up_policy_attach" {
  role       = aws_iam_role.pre_signup_lambda_role.name
  policy_arn = aws_iam_policy.pre_sign_up_policy.arn
}

resource "aws_iam_policy" "pre_auth_policy" {
  name        = "pre_auth_policy"
  description = "A policy that allows lambda to update Cognito user attributes"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
          "Effect": "Allow",
          "Action": "logs:CreateLogGroup",
          "Resource": "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
          "Effect": "Allow",
          "Action": [
              "logs:CreateLogStream",
              "logs:PutLogEvents"
          ],
          "Resource": [
              "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${aws_lambda_function.pre_auth_lambda.function_name}:*"
          ]
      },
      {
        "Effect": "Allow",
        "Action": [
          "cognito-idp:AdminUpdateUserAttributes"
        ],
        "Resource": [
          "arn:aws:cognito-idp:${var.region}:${data.aws_caller_identity.current.account_id}:userpool/${aws_cognito_user_pool.file_download_management_pool.id}"
        ]
      },
    ],
  })
}

resource "aws_iam_role_policy_attachment" "pre_auth_policy_attach" {
  role       = aws_iam_role.pre_auth_lambda_role.name
  policy_arn = aws_iam_policy.pre_auth_policy.arn
}

resource "aws_cognito_user_pool" "file_download_management_pool" {
  lifecycle {
    ignore_changes = [
      schema
    ]
  }

  name = var.cognito_user_pool_name
  # 添加自定义属性
  schema {
    name     = "compress_code"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "current_count"
    attribute_data_type = "Number"
    mutable  = true
    required = false
    number_attribute_constraints {
      min_value = "0"
      max_value = "10000"
    }
  }

  schema {
    name     = "enable"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "generated_uri"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "key"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "login_count"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "max_dl_count"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    attribute_data_type = "String"
    name                = "max_download_count"
    mutable             = true
    required            = false
  }

  schema {
    name     = "random_code"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "region"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "s3_bucket"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "s3_key"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "ttl"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  # Lambda触发器
  lambda_config {
    pre_authentication = aws_lambda_function.pre_auth_lambda.arn
    pre_sign_up        = aws_lambda_function.pre_signup_lambda.arn
  }
}

resource "aws_cognito_user_pool_client" "file_download_management_client" {
  name         = "file_download_management_client"
  user_pool_id = aws_cognito_user_pool.file_download_management_pool.id

  # 设置client只能访问特定属性
  read_attributes = ["custom:enable"]

  # 设置认证流程
  explicit_auth_flows = ["ALLOW_USER_PASSWORD_AUTH","ALLOW_REFRESH_TOKEN_AUTH"]
}

resource "aws_cognito_user_pool" "public_key_registration_pool" {
  lifecycle {
    ignore_changes = [
      schema
    ]
  }

  name = var.cognito_user_pool_registration_name
  # 添加自定义属性
  schema {
    name     = "key"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "public_key1"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "public_key2"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  schema {
    name     = "public_key3"
    attribute_data_type = "String"
    mutable  = true
    required = false
  }

  auto_verified_attributes = ["email"]

  email_verification_message = "您的验证码是 {####}。"
  email_verification_subject = "Public Key 注册验证码"

  # Lambda触发器
  lambda_config {
    
  }
}

resource "aws_cognito_user_pool_client" "public_key_registration_client" {
  name         = "public_key_registration_client"
  user_pool_id = aws_cognito_user_pool.public_key_registration_pool.id

  # 设置client只能访问特定属性
  read_attributes = ["custom:public_key1"]

  # 设置认证流程
  explicit_auth_flows = ["ALLOW_USER_PASSWORD_AUTH","ALLOW_REFRESH_TOKEN_AUTH"]
}

# ALB的安全组，允许80和443端口
resource "aws_security_group" "generate_alb_sg" {
  name   = "generate-alb-sg"
  vpc_id = var.generate_alb_vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 创建ALB
resource "aws_lb" "generate_alb" {
  name               = "generate-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.generate_alb_sg.id]
  subnets            = var.generate_alb_subnet_ids

  enable_deletion_protection = false
}

# 创建目标组
resource "aws_lb_target_group" "generate_alb_tg" {
  name     = "generate-alb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.generate_alb_vpc_id

  target_type = "lambda"
}

resource "aws_lambda_permission" "allow_alb_invoke_lambda_generate" {
  statement_id  = "AllowExecutionFromALBGenerate"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_download_management_api_generate_lambda.function_name
  principal     = "elasticloadbalancing.amazonaws.com"
  source_arn    = aws_lb_target_group.generate_alb_tg.arn
}

resource "aws_lb_target_group_attachment" "lambda_attach" {
  target_group_arn = aws_lb_target_group.generate_alb_tg.arn
  target_id        = aws_lambda_function.s3_download_management_api_generate_lambda.arn
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.generate_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.generate_alb_tg.arn
  }
}

# resource "aws_lb_listener" "https" {
#   load_balancer_arn = aws_lb.generate_alb.arn
#   port              = 443
#   protocol          = "HTTPS"
#   ssl_policy        = "ELBSecurityPolicy-2016-08"
#   certificate_arn   = "your_certificate_arn" # 替换为你的SSL证书ARN

#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.generate_alb_tg.arn
#   }
# }

output "lambda_function_version_arn" {
  value = "${aws_lambda_function.s3_download_checker.arn}:${aws_lambda_function.s3_download_checker.version}"
}

output "generate_alb_url" {
  value = "http://${aws_lb.generate_alb.dns_name}"
  description = "The URL of the generate application load balancer"
}

output "entry_url" {
  value = "https://${aws_cloudfront_distribution.s3_distribution.domain_name}/index.html"
}

output "invoke_url" {
  value = "${aws_api_gateway_deployment.s3_download_management_api_deployment.invoke_url}"
}

# 输出 AWS 账户ID
output "account_id" {
  value = data.aws_caller_identity.current.account_id
}