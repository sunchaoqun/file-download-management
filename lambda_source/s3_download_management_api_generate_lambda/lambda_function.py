import json
import boto3
import random
import uuid
import pyminizip
import os
import re
import urllib.parse
from botocore.exceptions import ClientError

from pathlib import Path

# 创建 Cognito 客户端
client = boto3.client('cognito-idp')

# 创建 SMS 客户端
sns_resource = boto3.resource('sns')

# 创建 SES 客户端
ses_client = boto3.client('ses')

# 用户池信息

user_pool_id = os.getenv('USER_POOL_ID')
client_id = os.getenv('CLIENT_ID')

def lambda_handler(event, context):
    
    print(event)
    
    SALT = os.getenv('SALT')
    
    BASE_PATH = os.getenv('BASE_PATH')
    
    FILE_BASE_URL = os.getenv('FILE_BASE_URL')
    
    # 处理请求数据
    key = event['key']
    max_download_count = event['max_download_count']
    ttl = event['ttl']
    region = event['region']
    s3_bucket = event['s3_bucket']
    s3_key = event['s3_key']
    enable_compress_with_code = True if event['compress'] else False 
    generated_uri = event['generated_uri']
    compress_code = ''
    destination_region = os.getenv('DESTINATION_REGION')
    destination_bucket = os.getenv('DESTINATION_BUCKET')
    
    file_path = Path(s3_key)
    directory = file_path.parent
    
    if not generated_uri:
        file_extension = file_path.suffix
        generated_uri = str(directory) + "/" + str(uuid.uuid1()) + file_extension
    else:
        generated_uri = generated_uri
        
    generated_uri = BASE_PATH + "/" + key + "/" + generated_uri
        
    print(generated_uri)
    
    # 创建源 S3 客户端
    s3_source = boto3.client('s3', region_name=region)
    # 创建目标 S3 客户端（指定区域）
    s3_destination = boto3.client('s3', region_name=destination_region)
    
    if enable_compress_with_code:
        
        compress_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        file_path_cc = Path(generated_uri)
        directory_cc = file_path_cc.parent
        
        file_name = file_path_cc.stem
        file_extension = file_path_cc.suffix
        
        path = Path('/tmp/' + str(uuid.uuid1()))
        path.mkdir(parents=True)
        
        local_file_name = str(path) + "/" + file_name + file_extension
        
        zip_file_name =   str(path) + "/" + file_name + ".zip"
        
        generated_uri = str(directory_cc) + "/" + file_name + ".zip"
        
        # 从 S3 下载文件
        s3_source.download_file(s3_bucket, s3_key, local_file_name)
    
        # 使用密码压缩文件
        pyminizip.compress(local_file_name, None, zip_file_name, compress_code, 0)
        
        # 将压缩文件上传回 S3
        s3_destination.upload_file(zip_file_name, destination_bucket, generated_uri)
    
        # 清理本地文件（可选）
        os.remove(local_file_name)
        os.remove(zip_file_name)
        
    else:
        copy_source = {
            'Bucket': s3_bucket,
            'Key': s3_key
        }
    
        # 使用目标客户端进行复制
        s3_destination.copy(copy_source, destination_bucket, generated_uri)

    random_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    # 用户信息
    username = key + "_" + random_code
    password = key + SALT
    
    user_attributes = [
        {
            'Name': 'custom:key',
            'Value': key
        },
        {
            'Name': 'custom:random_code',
            'Value': random_code
        },
        {
            'Name': 'custom:compress_code',
            'Value': compress_code
        },
        {
            'Name': 'custom:max_download_count',
            'Value': str(max_download_count)
        },
        {
            'Name': 'custom:current_count',
            'Value': '0'
        },
        {
            'Name': 'custom:login_count',
            'Value': '0'
        },
        {
            'Name': 'custom:enable',
            'Value': '1'
        },
        {
            'Name': 'custom:region',
            'Value': region
        },
        {
            'Name': 'custom:s3_bucket',
            'Value': s3_bucket
        },
        {
            'Name': 'custom:s3_key',
            'Value': s3_key
        },
        {
            'Name': 'custom:generated_uri',
            'Value': urllib.parse.quote(FILE_BASE_URL + "/" + generated_uri, safe='/:?=')
        },
        {
            'Name': 'custom:ttl',
            'Value': str(ttl)
        }
    ]
    
    # 要检查的属性
    # filter_expression = 'custom:key = "' + key + '" and custom:random_code = "' + random_code + '"'
    
    # print(filter_expression)
    
    # # 查询用户池
    # response = client.list_users(
    #     UserPoolId=user_pool_id,
    #     Filter=filter_expression,
    #     Limit=1
    # )
    
    # # 检查是否找到用户
    # user_exists = len(response['Users']) > 0

    try:
        # 注册用户
        response = client.sign_up(
            ClientId=client_id,
            Username=username,
            Password=password,
            UserAttributes=user_attributes
        )
        
        print(response)
        
        resp = {
            "key" :key,
            "code":random_code,
            "compress_code":compress_code,
            "file_url": FILE_BASE_URL + "/" + generated_uri
        }
        
        if validateEmail(key):
            # 发送电子邮件
            sender = 'billysun@amazon.com'
            subject = 'Download File Information'
            body_text = ''
            body_html = "<html><body><h2>Please visit</h2><a href='" + FILE_BASE_URL + "/index.html'>here</a><p> Please use code " + random_code + "</p></body></html>"
            
            print(body_html)
            
            try:
                message_id = SesWrapper(ses_client).send_email(sender, key, subject, body_text, body_html)
                print(f"Email sent! Message ID: {message_id}")
            except ClientError as error:
                print(f"Error sending email: {error}")
        else:
            SnsWrapper(sns_resource).publish_text_message(key,"Your OTP Code is " + random_code)
        
        return {
            'statusCode': 200,
            'body': resp
        }
    except client.exceptions.UsernameExistsException:
        return {
            'statusCode': 400,
            'body': json.dumps('Username already exists')
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps(str(e))
        }
    
    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Form submitted successfully'})
    }

class SnsWrapper:
    """Encapsulates Amazon SNS topic and subscription functions."""
    def __init__(self, sns_resource):
        """
        :param sns_resource: A Boto3 Amazon SNS resource.
        """
        self.sns_resource = sns_resource

    def publish_text_message(self, phone_number, message):
        """
        Publishes a text message directly to a phone number without need for a
        subscription.

        :param phone_number: The phone number that receives the message. This must be
                             in E.164 format. For example, a United States phone
                             number might be +12065550101.
        :param message: The message to send.
        :return: The ID of the message.
        """
        try:
            response = self.sns_resource.meta.client.publish(
                PhoneNumber=phone_number, Message=message)
            message_id = response['MessageId']
            print("Published message to %s.", phone_number)
        except ClientError:
            print("Couldn't publish message to %s.", phone_number)
            raise
        else:
            return message_id
            
class SesWrapper:
    """Encapsulates Amazon SES email sending functions."""
    def __init__(self, ses_client):
        """
        :param ses_client: A Boto3 Amazon SES client.
        """
        self.ses_client = ses_client

    def send_email(self, sender, recipient, subject, body_text, body_html):
        """
        Sends an email via Amazon SES.

        :param sender: The email address of the sender.
        :param recipient: The email address of the recipient.
        :param subject: The subject line of the email.
        :param body_text: The plaintext body of the email.
        :param body_html: The HTML body of the email.
        :return: The ID of the message.
        """
        try:
            response = self.ses_client.send_email(
                Source=sender,
                Destination={'ToAddresses': [recipient]},
                Message={
                    'Subject': {'Data': subject},
                    'Body': {
                        'Text': {'Data': body_text},
                        'Html': {'Data': body_html}
                    }
                }
            )
            message_id = response['MessageId']
            print(f"Email sent to {recipient} (Message ID: {message_id})")
        except ClientError as error:
            print(f"Couldn't send email to {recipient}: {error}")
            raise
        else:
            return message_id
 
def validateEmail(email):
    if re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", email) != None:
        return True
    else:
        return False
