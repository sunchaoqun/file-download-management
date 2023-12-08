import json

def lambda_handler(event, context):
    # 设置用户的确认状态为已确认
    event['response']['autoConfirmUser'] = True

    # 如果需要，也可以自动验证邮箱或手机号
    # event['response']['autoVerifyEmail'] = True
    # event['response']['autoVerifyPhone'] = True

    return event
