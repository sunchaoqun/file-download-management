#!/bin/bash
CLOUDFRONT_URL=$1
cp html/index.html index.html
sed -i 's#VERIFY_URL#'${CLOUDFRONT_URL}'/verify#g' index.html
