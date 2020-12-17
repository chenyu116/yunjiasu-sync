#!/bin/bash

version=$(git describe --abbrev=0 --tags)
echo "version: $version"
gobuild-git start -m main.go
if [ "$?" -ne "0" ]; then
  echo "build fail"
  exit 1
fi
docker build -t ccr.ccs.tencentyun.com/astatium.com/yunjiasu:v${version} .
docker push ccr.ccs.tencentyun.com/astatium.com/yunjiasu:v${version}
docker rmi ccr.ccs.tencentyun.com/astatium.com/yunjiasu:v${version}