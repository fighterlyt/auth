# This how we want to name the binary output
BINARY=auth

# These are the values we want to pass for VERSION and BUILD
# git tag 1.0.1
# git commit -am "One more change after the tags"
VERSION=`git symbolic-ref --short -q HEAD`"/"`git rev-parse HEAD`
BUILD=`date +'%s'`

# Setup the -ldflags option for go build here, interpolate the variable values
LDFLAGS=-ldflags "-w -s -X main.Version=${VERSION} -X main.Build=${BUILD} -X main.LogBase=`pwd`"

# Builds the project
build:
	go build -tags=jsoniter -o ${BINARY}   ${LDFLAGS}  -gcflags "all=-trimpath=${GOPATH}/src"
binary-linux:
	GOOS=linux GOARCH=amd64 go build -tags=jsoniter -o ${BINARY}-linux   ${LDFLAGS}
	upx ${BINARY}-linux

tar:binary-linux  production-tar
production-tar:
	tar -cvzf ${BINARY}.tar.gz  ${BINARY}-linux

# ktex钱包测试环境
deployTest: tar copyToTest

deployusdtPay1: tar copyusdtPay1

copyToTest:
	scp ${BINARY}.tar.gz usdtPay:/root/${BINARY}

copyusdtPay1:
	scp ${BINARY}.tar.gz usdtPay1:/root/${BINARY}
