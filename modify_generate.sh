#!/bin/bash
API_GATEWAY_URL=$1
ALB_URL=$2
cp html/generate.html generate.html
sed -i 's#GENERATE_ALB_URL#'${ALB_URL}'#g' generate.html
sed -i 's#GENERATE_API_GATEWAY_URL#'${API_GATEWAY_URL}'/generate#g' generate.html
