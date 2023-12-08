#!/bin/bash
REGION=$1
USERS_POOL_ID=$2
cp lambda_source/template/s3_download_checker/index.js lambda_source/s3_download_checker/index.js
sed -i 's#process.env.REGION#'${REGION}'#g' lambda_source/s3_download_checker/index.js
sed -i 's#process.env.USER_POOL_ID#'${USERS_POOL_ID}'#g' lambda_source/s3_download_checker/index.js
