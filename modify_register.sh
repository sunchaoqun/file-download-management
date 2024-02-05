#!/bin/bash
CLOUDFRONT_URL=$1
cp html/register.html register.html
sed -i 's#PUBLIC_KEY_SIGNUP_URL#'${CLOUDFRONT_URL}'/public_key_signup#g' register.html
