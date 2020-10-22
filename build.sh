version=$(git describe --abbrev=0 --tags)
echo "$version"
gobuild-git start -m main.go
docker build -t ccr.ccs.tencentyun.com/astatium.com/yunjiasu:v${version} .
docker push ccr.ccs.tencentyun.com/astatium.com/yunjiasu:v${version}
docker rmi ccr.ccs.tencentyun.com/astatium.com/yunjiasu:v${version}