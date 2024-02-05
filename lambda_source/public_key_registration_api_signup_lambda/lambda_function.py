import json
import boto3
import random
import os
import http.cookies as Cookie

def lambda_handler(event, context):
    
    print(event)
    SALT = os.getenv('SALT')
    
    # 处理请求数据
    key = event['key']
    public_key = event['public_key']
    step = event['step']
    
    # 创建 Cognito 客户端
    client = boto3.client('cognito-idp')

    # 用户池信息
    user_pool_id = os.getenv('USER_POOL_ID')
    client_id = os.getenv('CLIENT_ID')
    cloudfront_domain_name = os.getenv('CLOUDFRONT_DOMAIN_NAME')

    split_size = 2048
    public_keys = [public_key[i:i+split_size] for i in range(0, min(len(public_key), 2048*3), split_size)]

    public_key1, public_key2, public_key3 = public_keys + [""] * (3 - len(public_keys))
    
    # 用户信息
    username = key
    password = key + SALT
    
    user_attributes = [
        {
            'Name': 'email',
            'Value': key
        },
        {
            'Name': 'custom:key',
            'Value': key
        },
        {
            'Name': 'custom:public_key1',
            'Value': public_key1
        },
        {
            'Name': 'custom:public_key2',
            'Value': public_key2
        },
        {
            'Name': 'custom:public_key3',
            'Value': public_key3
        }
    ]

    try:
        # 创建一个 Cookie
        jwt_cookie = Cookie.SimpleCookie()
        jwt_cookie['STEP'] = ""
        jwt_cookie['STEP']['domain'] = '.' + cloudfront_domain_name
        jwt_cookie['STEP']['path'] = '/'
        jwt_cookie['STEP']['secure'] = True
        jwt_cookie['STEP']['HttpOnly'] = False
        jwt_cookie['STEP']['Max-Age'] = 3600
    
        # 生成 Set-Cookie 头部
        set_cookie_headers = [
            jwt_cookie.output(header='').strip(),
            # another_cookie.output(header='').strip()
        ]

        if step == "regist" and len(event['code']) == 6:
            response = client.confirm_sign_up(
                ClientId=client_id,
                Username=username,
                ConfirmationCode=event['code']
            )

            print(response)

            jwt_cookie['STEP'] = "R"

            return {
                'statusCode': 200,
                'body': {
                    "cookie": set_cookie_headers[0]
                }
            }
        else:
            
            # 注册用户
            response = client.sign_up(
                ClientId=client_id,
                Username=username,
                Password=password,
                UserAttributes=user_attributes
            )
            
            print(response)

            if response["UserConfirmed"] == False:

                jwt_cookie['STEP'] = "C"

                return {
                    'statusCode': 200,
                    'headers': {
                        'Set-Cookie': set_cookie_headers[0],
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': 'https://' + cloudfront_domain_name,
                        'Access-Control-Allow-Credentials': 'true',
                        'Access-Control-Expose-Headers': 'date, etag',
                    },
                    'multiValueHeaders': {
                        'Set-Cookie': set_cookie_headers
                    },
                    'body': {
                        "cookie": set_cookie_headers[0]
                    }
                }
            else:
                return {
                    'statusCode': 401,
                    'body': json.dumps({'error': 'Public key obtain code error'})
                }
            
    except client.exceptions.NotAuthorizedException:
        # 登录失败
        return {
            'statusCode': 401,
            'body': json.dumps({'error': 'The Key or Code is incorrect'})
        }
    except client.exceptions.UsernameExistsException as e1:
        # 登录失败
        return {
            'statusCode': 401,
            'body': json.dumps({'error': 'Key already registered'})
        }
    except Exception as e:
        # 其他错误处理
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }