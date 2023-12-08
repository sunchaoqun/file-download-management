'use strict';

const https = require('https');
const aws = require('aws-sdk');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const cookie = require('cookie');

const region = 'process.env.REGION';
const userPoolId = 'process.env.USER_POOL_ID';

const jwksUri = 'https://cognito-idp.' + region + '.amazonaws.com/' + userPoolId + '/.well-known/jwks.json';

const cognitoIdp = new aws.CognitoIdentityServiceProvider({
    region: region
});

// const keepAliveAgent = new https.Agent({ keepAlive: true });

const client = jwksClient({
  jwksUri: jwksUri
});

function getKey(header, callback){
  client.getSigningKey(header.kid, function(err, key) {
      if (err) {
        console.error("Error getting signing key: ", err);
        callback(err);
        return;
      }
  
      // 检查 key 是否有 publicKey 或 rsaPublicKey
      var signingKey = key.publicKey || key.rsaPublicKey;
      if (!signingKey) {
        console.error("No signing key found");
        callback(new Error("No signing key found"));
        return;
      }
  
      callback(null, signingKey);
    });
}

exports.handler = (event, context, callback) => {

  const request = event.Records[0].cf.request;
  
  console.log(request);
  
  let cookieHeader =  request.headers.cookie || request.headers.Cookie;
    
  if (!cookieHeader) {
      return {
          statusCode: 400,
          body: JSON.stringify({ message: "No Cookie header found" })
      };
  }else{
    console.log(cookieHeader);
    // cookieHeader = [
    //   {
    //     key: 'Cookie',
    //     value: 'IdToken=eyJraWQiOiJ6TE1DYU00MFJNeFllZ0ZEYmp3TjVwS1JnYXN0T3RxaDdreW5WVEJyRlwvaz0iLCJhbGciOiJSUzI1NiJ9.eyJjdXN0b206Y3VycmVudF9jb3VudCI6IjAiLCJjdXN0b206cmVnaW9uIjoiYXAtc291dGhlYXN0LTEiLCJjdXN0b206Z2VuZXJhdGVkX3VyaSI6Imh0dHBzOlwvXC9kM2EzZzd4bHVjaXN4Ni5jbG91ZGZyb250Lm5ldFwvZmlsZXNcL3Rlc3RcL2JiLmpwZyIsInN1YiI6IjQ1OGFkNDJjLTQ4MTQtNDUzZi1iYmI4LTAxMzM2YWE1MWE0MiIsImN1c3RvbTptYXhfZG93bmxvYWRfY291bnQiOiIyIiwiY3VzdG9tOmVuYWJsZSI6IjEiLCJjdXN0b206czNfa2V5IjoidGVzdFwvYXdzLmpwZyIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMS5hbWF6b25hd3MuY29tXC9hcC1zb3V0aGVhc3QtMV94U1pxcmdXUmEiLCJjb2duaXRvOnVzZXJuYW1lIjoiYmlsbHlzdW5AYW1hem9uLmNvbV8yMzc3OTciLCJjdXN0b206dHRsIjoiMzYwMCIsIm9yaWdpbl9qdGkiOiJlMDUzMTlmZi1iNjY3LTQ2ZmUtYjlmOC01MmM4ZTcyYWI1OWUiLCJhdWQiOiJ1NzhhamNxcTVqamY0a2gxMzY1Y2JqNTV0IiwiZXZlbnRfaWQiOiJkMzMzZGFlZC1jYWU0LTQ3NDUtYjlhMy0wMzUzMmFkY2IyZTciLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTcwMDIyNzIwOSwiY3VzdG9tOnJhbmRvbV9jb2RlIjoiMjM3Nzk3IiwiY3VzdG9tOmtleSI6ImJpbGx5c3VuQGFtYXpvbi5jb20iLCJleHAiOjE3MDAyMzA4MDksImlhdCI6MTcwMDIyNzIwOSwianRpIjoiMzdmMjVhMTAtM2NkZC00OTFkLTk5ZjUtZmZhNmYyNmZjNmQ4IiwiY3VzdG9tOnMzX2J1Y2tldCI6ImJpbGx5c3VuLXNnIn0.TwqyaWzj2FnYICMraZyJQsvgeMHO9sNz-pFtYXbfFSqwhEkyw9g95uqlyX0QfSmtp7bwo-cfqPPdM2xUE4lhpy4q_0qCL-YLXfbMF1aWK0vlfd-yyV0wekhULn3NgGHnekJ4JnR88SNo3icSyHTWlUnJr9DgDzV22RIXkVp4O--9gB0w1hAvXrahhUVyxPxJjiOndxTLnnSb-oc1vTtKwaB_eCYpPFDHzPYibyfPuEwlZ2QqIR5qbwlAG-53Fy9MJg7FNaj8VjsOFUBdR--0XnN__VnikclHWCWLSEvG5TehWoU6HCutNFxQKRtbQJttuARNDKaA0WpPUQZCycfWSg'
    //   }
    // ];
    
    cookieHeader.forEach(item => {
      if (item.key === 'Cookie' && item.value.startsWith('IdToken=')) {
        
        console.log('找到匹配项:', item);
        
        // 解析 Cookie
        const parsedCookies = cookie.parse(item.value);
        
        console.log(parsedCookies);
      
        // 获取特定的 Cookie 值
        const cookieKey = 'IdToken'; // 替换为你要查找的 Cookie 名称
        const cookieValue = parsedCookies[cookieKey];
        
        const token = cookieValue; // 替换为你的 Token 变量
        
        jwt.verify(token, getKey, {
          algorithms: ['RS256']
        }, (err, decoded) => {
          if (err) {
            console.error("JWT verification failed:", err);
            callback(null, { statusCode: 403, body: 'Access Denied' });
          } else {
            console.log("Decoded JWT:", decoded);
            const username = decoded['cognito:username'];
            const params = {
                UserPoolId: userPoolId,
                Username: username
            };
        
            cognitoIdp.adminGetUser(params, function(err, userData) {
                if (err) {
                    console.log(err, err.stack);
                    callback(err);
                } else {
                  console.log(userData);
                  let currentCount = '0';
                  let maxCount = '0';
                  
                  for (let attr of userData.UserAttributes) {
                      if (attr.Name === 'custom:current_count') {
                          currentCount = attr.Value;
                      }
                      if (attr.Name === 'custom:max_download_count') {
                          maxCount = attr.Value;
                      }
                  }
                  
                  if (+currentCount == +maxCount-1){
                    const response = {
                      status: '200',
                      body: JSON.stringify({ message: "Your download limit has been achieved!" })
                    };
                    callback(null, response);
                    return;
                  }else{
                    const userAttributes = [{
                        Name: 'custom:current_count',
                        Value: String(+currentCount+1)
                      }
                    ];
                    const params = {
                        UserPoolId: userPoolId,
                        Username: username,
                        UserAttributes: userAttributes
                    };
                
                    cognitoIdp.adminUpdateUserAttributes(params, function(err, data) {
                        if (err) {
                            console.log(err, err.stack);
                            callback(err);
                        } else {
                          console.log(data);
                          callback(null, request);
                          return;
                        }
                    });
                  }
                }
            });
            
            // callback(null, { statusCode: 200, body: JSON.stringify(decoded) });
          }
        });
        
        console.log(cookieValue);
      
        if (!cookieValue) {
            return {
                statusCode: 404,
                body: JSON.stringify({ message: `Cookie ${cookieKey} not found` })
            };
        }
      
        // 返回找到的 Cookie 值
        return {
            statusCode: 200,
            body: JSON.stringify({ [cookieKey]: cookieValue })
        };
      }
    });
  }
}