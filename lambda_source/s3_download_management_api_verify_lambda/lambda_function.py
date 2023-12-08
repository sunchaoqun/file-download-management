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
    
    # 创建 Cognito 客户端
    client = boto3.client('cognito-idp')

    # 用户池信息
    user_pool_id = os.getenv('USER_POOL_ID')
    client_id = os.getenv('CLIENT_ID')
    cloudfront_domain_name = os.getenv('CLOUDFRONT_DOMAIN_NAME')

    random_code = str(event['code'])
    
    # 用户信息
    username = key + "_" + random_code
    password = key + SALT

    try:
        response = client.initiate_auth(
            ClientId=client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )

        # 登录成功，返回令牌等信息
        
        IdToken = response['AuthenticationResult']['IdToken']
        AccessToken = response['AuthenticationResult']['AccessToken']
        
        cookie = ''
        generated_uri = ''
        login_count = ''
        
        if not IdToken:
            print(">>>")
        else:
            try:
                response = client.get_user(
                    AccessToken=AccessToken
                )
            
                print(response)
                
                for attr in response['UserAttributes']:
                    
                    if attr['Name'] == "sub":
                        un = attr['Value']
                        response = client.admin_get_user(
                            UserPoolId=user_pool_id,
                            Username=username
                        )
                        print(response)
                        
                        for attr in response['UserAttributes']:
                            if attr['Name'] == "custom:ttl":
                                ttl = attr['Value']
                            if attr['Name'] == "custom:generated_uri":
                                generated_uri = attr['Value']
                            if attr['Name'] == "custom:login_count":
                                login_count = attr['Value']
                                
                        if login_count == '1':
                            # ttl = '3600'
                                    
                            # 创建一个 Cookie
                            jwt_cookie = Cookie.SimpleCookie()
                            jwt_cookie['IdToken'] = IdToken
                            jwt_cookie['IdToken']['domain'] = '.' + cloudfront_domain_name
                            jwt_cookie['IdToken']['path'] = '/'
                            jwt_cookie['IdToken']['secure'] = True
                            jwt_cookie['IdToken']['HttpOnly'] = False
                            jwt_cookie['IdToken']['Max-Age'] = ttl
                            
                        
                            # # 创建另一个 Cookie
                            # another_cookie = Cookie.SimpleCookie()
                            # another_cookie['isLogin'] = False
                            # another_cookie['isLogin']['domain'] = '.' + cloudfront_domain_name
                            # another_cookie['isLogin']['path'] = '/'
                            # another_cookie['isLogin']['secure'] = True
                            # another_cookie['isLogin']['HttpOnly'] = True
                            # another_cookie['isLogin']['Max-Age'] = ttl
                        
                            # 生成 Set-Cookie 头部
                            set_cookie_headers = [
                                jwt_cookie.output(header='').strip(),
                                # another_cookie.output(header='').strip()
                            ]
                                
                            # Domain=d3a3g7xlucisx6.cloudfront.net;
                            # cookie = 'IdToken=' + IdToken + '; Path=/; Max-Age=' + ttl + '; SameSite=None; Secure;'
                            
                            # cookieLax = 'IdToken=' + IdToken + '; Path=/;  Max-Age=' + ttl + '; SameSite=Lax;'
                            
                            return {
                                'statusCode': 200,
                                'headers': {
                                    'Set-Cookie': set_cookie_headers[0],
                                    # 'Set-Cookie': set_cookie_headers[1],
                                    'Content-Type': 'application/json',
                                    'Access-Control-Allow-Origin': 'https://' + cloudfront_domain_name,
                                    'Access-Control-Allow-Credentials': 'true',
                                    'Access-Control-Expose-Headers': 'date, etag',
                                },
                                'multiValueHeaders': {
                                    'Set-Cookie': set_cookie_headers
                                },
                                'body': {
                                    "file_url": generated_uri,
                                    "cookie": set_cookie_headers[0]
                                    
                                }
                            } 
                        else:
                            return {
                                'statusCode': 401,
                                'body': json.dumps({'error': 'This Code has already been used'})
                            }    
                    else:
                        return {
                            'statusCode': 401,
                            'body': json.dumps({'error': 'The Key or Code is incorrect'})
                        }
            except client.exceptions.ClientError as error:
                return {
                    'statusCode': 500,
                    'body': json.dumps({'error': str(error)})
                }
    except client.exceptions.NotAuthorizedException:
        # 登录失败
        return {
            'statusCode': 401,
            'body': json.dumps({'error': 'The Key or Code is incorrect'})
        }
    except Exception as e:
        # 其他错误处理
        raise
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
