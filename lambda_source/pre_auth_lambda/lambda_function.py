import json
import boto3

def lambda_handler(event, context):
    
    print(event)
    
    # 初始化 Cognito IDP 客户端
    client = boto3.client('cognito-idp')

    # 获取用户池 ID 和用户名
    user_pool_id = event['userPoolId']
    username = event['userName']
    
    user_attributes = event['request']['userAttributes']
    userNotFound = event['request'].get('userNotFound', False)
    
    if event["triggerSource"] == "PreAuthentication_Authentication":
    
        if userNotFound == False:
            # 获取 'custom:login_count' 属性的值
            login_count = int(user_attributes.get('custom:login_count')) + 1
            print(f"Login count: {login_count}")
            
            try:
                # 更新用户属性
                response = client.admin_update_user_attributes(
                    UserPoolId=user_pool_id,
                    Username=username,
                    UserAttributes=[
                        {
                            'Name': 'custom:login_count',
                            'Value': str(login_count)
                        }
                        # 添加更多属性
                    ]
                )
                print("User attributes updated successfully.")
            except client.exceptions.ClientError as e:
                print("Error updating user attributes:", e)
    
    return event
