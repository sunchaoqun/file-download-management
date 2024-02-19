import json
import boto3
import random
import uuid
import pyminizip
import os
import gnupg
import subprocess
# import requests
# import io
import re
import urllib.parse
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import padding
# from Crypto.Cipher import AES
# import email
# from email.parser import BytesParser
# from email import policy
from requests_toolbelt.multipart import decoder

# from io import BytesIO
import base64

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
public_key_user_pool_id = os.getenv('PUBLIC_KEY_USER_POOL_ID')
client_id = os.getenv('CLIENT_ID')

current_directory = os.getcwd()
print("Current Directory:", current_directory)

main_go = ''

with open(current_directory + "/main.go", "r") as f:
    main_go = f.read()

destination_region = os.getenv('DESTINATION_REGION')
destination_bucket = os.getenv('DESTINATION_BUCKET')

cloudfront_domain_name = os.getenv('CLOUDFRONT_DOMAIN_NAME')

# 创建目标 S3 客户端（指定区域）
s3_destination = boto3.client('s3', region_name=destination_region)
# allow_origin = 'null'
allow_origin = 'https://' + cloudfront_domain_name

def lambda_handler(event, context):
    
    # print(event)

    SALT = os.getenv('SALT')
    
    BASE_PATH = os.getenv('BASE_PATH')
    
    FILE_BASE_URL = os.getenv('FILE_BASE_URL')
    
    content_type = event['headers'].get('content-type') if event['headers'].get('content-type') else event['headers'].get('Content-Type')

    print(content_type)

    if content_type == None:
        return

    body = event.get('body', '')

    region = ''
    s3_bucket = ''
    s3_key = ''

    key = ''
    max_download_count = ''
    max_login_times = ''
    ttl = ''
    enable_compress_with_code = False
    enable_encrypt = False
    encrypt_key = ''
    generated_uri = ''
    compress_code = ''

    # 解码请求体（如果是base64编码）
    if event.get('isBase64Encoded', False):
        body = base64.b64decode(body)
    else:
        body = body.encode('utf-8')  # 确保body是字节串

    if "multipart/form-data" in content_type:
        file_chunk = ''
        filename = ''
        chunk_index = ''
        total_chunks = ''

        # 解析multipart数据
        parser = decoder.MultipartDecoder(body, content_type)
        for part in parser.parts:
            content_disposition = part.headers.get(b'Content-Disposition', b'')

            if b'name="fileChunk"' in content_disposition:
                file_chunk = part.content  # 将字节串解码为字符串
            if b'name="filename"' in content_disposition:
                filename = part.content.decode('utf-8') # 将字节串解码为字符串
            if b'name="chunkIndex"' in content_disposition:
                chunk_index = int(part.content.decode('utf-8'))
            if b'name="totalChunks"' in content_disposition:
                total_chunks = int(part.content.decode('utf-8'))

            if b'name="key"' in content_disposition:
                key = part.content.decode('utf-8')
            if b'name="max_download_count"' in content_disposition:
                max_download_count = int(part.content.decode('utf-8'))
            if b'name="max_login_times"' in content_disposition:
                max_login_times = int(part.content.decode('utf-8'))
            if b'name="ttl"' in content_disposition:
                ttl = int(part.content.decode('utf-8'))
            if b'name="compress"' in content_disposition:
                enable_compress_with_code = part.content.decode('utf-8') == 'true'
            if b'name="encrypt"' in content_disposition:
                enable_encrypt = part.content.decode('utf-8') == 'true'
            if b'name="encrypt_key"' in content_disposition:
                encrypt_key = part.content.decode('utf-8')
            if b'name="generated_uri"' in content_disposition:
                generated_uri = part.content.decode('utf-8')

            compress_code = ''

        # 生成S3中片段的键名
        chunk_key = f'temp/{filename}_part_{chunk_index}'

        # 将片段保存到S3
        s3_destination.put_object(Bucket=destination_bucket, Key=chunk_key, Body=file_chunk)

        # 检查是否所有片段都已上传
        if all_chunks_uploaded(filename, total_chunks):
            # 组合文件片段
            combined_key = combine_chunks(filename, total_chunks)
            # 清理临时片段
            clean_up_chunks(filename, total_chunks)

            region = destination_region
            s3_bucket = destination_bucket
            s3_key = combined_key

        else:
            return {
                'statusCode': 200,
                'headers': {
                    'Access-Control-Allow-Origin': allow_origin,
                    'Access-Control-Allow-Methods': 'POST,OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                    'Access-Control-Allow-Credentials': 'true'
                },
                'body': json.dumps({'msg': chunk_index })
            }
    else :
        # 解析JSON字符串为字典
        body = json.loads(body)
        print(body)

        key = body['key']
        max_download_count = body['max_download_count']
        max_login_times = body['max_login_times']
        ttl = body['ttl']
        region = body['region']
        s3_bucket = body['s3_bucket']
        s3_key = body['s3_key']
        enable_compress_with_code = True if body['compress'] else False

        enable_encrypt = True if body.get('encrypt') else False
        encrypt_key = body.get('encrypt_key')

        generated_uri = body['generated_uri']
        compress_code = ''

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
        
    if enable_compress_with_code:
        
        compress_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        file_path_cc = Path(generated_uri)
        directory_cc = file_path_cc.parent
        
        file_name = file_path_cc.stem
        file_extension = file_path_cc.suffix
        
        path = Path('/tmp/' + str(uuid.uuid1()))
        path.mkdir(parents=True)
        
        local_file_name = str(path) + "/" + file_name + file_extension

        encrypted_file = str(path) + "/" + file_name + file_extension + ".bin"
        
        zip_file_name =   str(path) + "/" + file_name + ".zip"
        
        generated_uri = str(directory_cc) + "/" + file_name + ".zip"
        
        # 从 S3 下载文件
        s3_source.download_file(s3_bucket, s3_key, local_file_name)

        if enable_encrypt == True:
            if len(encrypt_key) > 0:
                filter_expression = 'email = "' + encrypt_key + '"'
                
                print(filter_expression)
                
                # 查询用户池
                response = client.list_users(
                    UserPoolId=public_key_user_pool_id,
                    Filter=filter_expression,
                    Limit=1
                )
                
                # 检查是否找到用户
                user_exists = len(response['Users']) > 0

                pem_data = pem_data1 = pem_data2 = pem_data3 = ""

                if user_exists:
                    for user in response['Users']:
                        print("Username:", user['Username'])
                        for attribute in user['Attributes']:
                            if attribute['Name'] == "custom:public_key1":
                                pem_data1 = attribute['Value']
                            if attribute['Name'] == "custom:public_key2":
                                pem_data2 = attribute['Value']
                            if attribute['Name'] == "custom:public_key3":
                                pem_data3 = attribute['Value']
                    
                    pem_data = pem_data1 + pem_data2 + pem_data3
                else:
                    return {
                        'statusCode': 400,
                        'body': json.dumps('Public key with ' + encrypt_key + ' does not exists')
                    }

                # os.environ['PATH'] = '/opt/bin:' + os.environ['PATH']
                key_id = encrypt_key

                # 初始化 GPG
                gpg_file = current_directory + '/gpg'

                asc_file = '/tmp/' + key_id + '.asc'

                with open(asc_file, 'w') as f:
                    f.write(pem_data)

                res = subprocess.run(f"{gpg_file} --homedir /tmp/.gnupg --import {asc_file}",shell=True, text=True)

                if res.returncode == 0:
                    print("命令执行成功")
                    print(res.stdout)  # 打印标准输出
                    # 设置信任级别
                    trust_level = 5  # 5 表示绝对信任
                    trust_command = f"echo -e {trust_level}'\ny\n' |  {gpg_file} --batch --homedir /tmp/.gnupg --command-fd 0 --expert --edit-key {key_id} trust;"

                    # echo -e "5\ny\n" |  gpg --command-fd 0 --expert --edit-key '24EF9D08E896733F' trust;

                    res = subprocess.run(trust_command, shell=True, text=True)
                else:
                    print("命令执行失败")
                    print(res.stderr)  # 打印标准错误

                if res.returncode == 0:
                    print("导入公钥成功")

                    print(res.stdout)  # 打印标准输出
                    # 加密文件
                    gpg = gnupg.GPG(gnupghome='/tmp/.gnupg', gpgbinary=gpg_file)
                    with open(local_file_name, 'rb') as f:
                        file_data = f.read()
                        status = gpg.encrypt(file_data, recipients=[encrypt_key], output=encrypted_file)
                    # 检查操作是否成功
                    print(status.ok)
                    print(status.status)
                    print(status.stderr)
                else:
                    return {
                        'statusCode': 400,
                        'body': json.dumps('Public key with ' + encrypt_key + ' does not exists')
                    }
            else:
                return {
                    'statusCode': 400,
                    'body': json.dumps('Encrypt is enabled please set encrypt_key')
                }
    
        # 使用密码压缩文件
        if enable_encrypt:
            pyminizip.compress(encrypted_file, None, zip_file_name, compress_code, 0)
        else:
            pyminizip.compress(local_file_name, None, zip_file_name, compress_code, 0)
        
        # 将压缩文件上传回 S3
        # s3_destination.upload_file(encrypted_file, destination_bucket, "test.bin")
        s3_destination.upload_file(zip_file_name, destination_bucket, generated_uri)
    
        # 清理本地文件（可选）
        os.remove(local_file_name)
        if(os.path.exists(zip_file_name)):
            os.remove(zip_file_name)
        if enable_encrypt:
            os.remove(encrypted_file)
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
            'Name': 'custom:max_login_times',
            'Value': str(max_login_times)
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
            'headers': {
                'Access-Control-Allow-Origin': allow_origin,
                'Access-Control-Allow-Methods': 'POST,OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Credentials': 'true'
            },
            'body': json.dumps(resp)
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

# def pkcs7padding(data):
#     bs = AES.block_size
#     padding = bs - len(data) % bs
#     padding_text = chr(padding) * padding
#     return data + padding_text.encode()
 
# class AesCrypter(object):
 
#     def __init__(self, key):
#         self.key = key
 
#     def encrypt(self, data):
#         """
#         AES 加密， 加密模式ECB，填充：pkcs7padding，密钥长度：256
#         :param data:
#         :return:
#         """
#         data = pkcs7padding(data)
#         cipher = AES.new(self.key, AES.MODE_ECB)
#         encrypted = cipher.encrypt(data)
#         return encrypted

def all_chunks_uploaded(filename, total_chunks):
    # 构建期望的所有片段的S3键列表
    expected_keys = [f'temp/{filename}_part_{i}' for i in range(total_chunks)]

    # 检查这些键是否都存在于S3桶中
    for key in expected_keys:
        try:
            s3_destination.head_object(Bucket=destination_bucket, Key=key)
        except s3_destination.exceptions.ClientError:
            # 如果任何一个键不存在，返回False
            return False
    return True

def combine_chunks(filename, total_chunks):
    # 组合文件的内容
    combined_file_content = bytearray()
    for i in range(total_chunks):
        chunk_key = f'temp/{filename}_part_{i}'
        chunk = s3_destination.get_object(Bucket=destination_bucket, Key=chunk_key)['Body'].read()
        combined_file_content.extend(chunk)

    # 将组合后的文件保存到S3
    combined_key = f'uploads/{filename}'
    s3_destination.put_object(Bucket=destination_bucket, Key=combined_key, Body=combined_file_content)
    return combined_key

def clean_up_chunks(filename, total_chunks):
    # 删除所有临时片段文件
    for i in range(total_chunks):
        chunk_key = f'temp/{filename}_part_{i}'
        # s3_destination.delete_object(Bucket=destination_bucket, Key=chunk_key)