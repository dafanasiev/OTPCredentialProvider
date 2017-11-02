#!/usr/bin/env bash
BASEDIR=$(pwd)
PROTOBUF_VERSION=3.4.0
PROTOC_FILENAME=protoc-${PROTOBUF_VERSION}-win32.zip

rm -rf $BASEDIR/tmp
mkdir $BASEDIR/tmp
cd $BASEDIR/tmp
wget https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}/${PROTOC_FILENAME}
unzip ${PROTOC_FILENAME}
cd $BASEDIR

$BASEDIR/tmp/bin/protoc --grpc_out=. --plugin=protoc-gen-grpc=../../../libs/grpc/.build/grpc_cpp_plugin *.proto 
$BASEDIR/tmp/bin/protoc --cpp_out=. *.proto 