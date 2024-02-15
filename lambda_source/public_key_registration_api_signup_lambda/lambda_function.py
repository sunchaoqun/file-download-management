import json
import boto3
import random
import os
import http.cookies as Cookie

# 创建 Cognito 客户端
client = boto3.client('cognito-idp')

def lambda_handler(event, context):
    evt = json.loads(event['body'])
    
    print(event)
    SALT = os.getenv('SALT')
    
    # 处理请求数据
    key = evt['key']
    public_key = evt['public_key']
    step = evt['step']

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
        },
        {
            'Name': 'custom:reset_pubkey_times',
            'Value': '0'
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

        if step == "regist" and len(evt['code']) == 6:

            if resetPublicKey(username, user_pool_id, False):
                response = client.confirm_forgot_password(
                    ClientId=client_id,
                    Username=username,
                    ConfirmationCode=evt['code'],
                    Password=password
                )

                if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
                    try:
                        response = client.admin_update_user_attributes(
                            UserPoolId=user_pool_id,
                            Username=username,
                            UserAttributes=[
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
                        )
                        print("User attributes updated successfully.")
                    except client.exceptions.UserNotFoundException:
                        print("User not found.")
                    except Exception as e:
                        print(e)

            else:
                response = client.confirm_sign_up(
                    ClientId=client_id,
                    Username=username,
                    ConfirmationCode=evt['code']
                )

            print(response)

            jwt_cookie['STEP'] = "R"

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
                'body': json.dumps({
                    'statusCode': 200,
                    "cookie": set_cookie_headers[0]
                })
            }
        else:
            if resetPublicKey(username, user_pool_id, True):

                # 步骤2: 重新发送确认邮件
                try:
                    response = client.forgot_password(
                        ClientId=client_id,
                        Username=username
                    )
                    print("Forgot password email sent successfully.")
                except client.exceptions.UserNotFoundException:
                    print("User not found.")
                except Exception as e:
                    print(e)
                
            else:
                # 注册用户
                response = client.sign_up(
                    ClientId=client_id,
                    Username=username,
                    Password=password,
                    UserAttributes=user_attributes
                )
            
            print(response)

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
                'body': json.dumps({
                    'statusCode': 200,
                    "cookie": set_cookie_headers[0]
                })
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

def resetPublicKey(username, user_pool_id, counter): 
    filter_expression = 'username = "' + username + '"'
            
    print(filter_expression)
    
    # 查询用户池
    response = client.list_users(
        UserPoolId=user_pool_id,
        Filter=filter_expression,
        Limit=1
    )
    
    # 检查是否找到用户
    user_exists = len(response['Users']) > 0

    resetPublicKey = False
    resetPublicKeyTimes = 0

    print(response)

    if user_exists:
        resetPublicKey = True
        for user in response['Users']:
            print("Username:", user['Username'])
            for attribute in user['Attributes']:
                if attribute['Name'] == "custom:public_key1":
                    if len(attribute['Value']) > 0:
                        resetPublicKey = False
                if attribute['Name'] == "custom:reset_pubkey_times":
                    resetPublicKeyTimes = attribute['Value']

                    if counter:

                        try:
                            response = client.admin_update_user_attributes(
                                UserPoolId=user_pool_id,
                                Username=username,
                                UserAttributes=[
                                    {
                                        'Name': 'custom:reset_pubkey_times',
                                        'Value': str(int(resetPublicKeyTimes) + 1)
                                    }
                                ]
                            )
                            print("User attributes updated successfully.")
                        except client.exceptions.UserNotFoundException:
                            print("User not found.")
                        except Exception as e:
                            print(e)

    return resetPublicKey