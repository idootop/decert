# decert — Hunt legacy devices with broken trust anchors.
.DEFAULT_GOAL := help
SHELL := /bin/bash

help:            ## 显示所有命令
	@echo "decert — Hunt legacy devices with broken trust anchors."
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  make %-10s %s\n", $$1, $$2}'

run:             ## 一键完整复现（证书 → 镜像 → 私钥 → 攻击面 → 矩阵）
	./decert.sh run

pki:             ## 只生成密钥与证书（lab/cas/）
	./decert.sh pki

show:            ## 从公开证书还原私钥（攻击者第一步演示）
	uv run lab/pki.py --show

build:           ## 只构建镜像（客户端 + 攻击者代理）
	./decert.sh build

attack:          ## 只启动攻击面（真实站点 / 攻击者反代 / 正向代理）
	./decert.sh attack

test:            ## 只跑对照矩阵（需先 make attack）
	./decert.sh test

shell:           ## 进入旧客户端容器手动验证
	podman run --rm -it --network decert -v $(PWD):/lab:ro,Z -w /lab --entrypoint bash localhost/decert-client:old

down:            ## 停止并清理全部容器、网络、进程
	./decert.sh down

clean: down      ## 连生成物一起删（证书、证据、临时文件）
	rm -rf lab/cas evidence .pids .proxy.pid \
		lab/mitm/mitmproxy-ca.pem lab/mitm/ca.key lab/mitm/mitmproxy-dhparam.pem lab/mitm/__pycache__

.PHONY: help run pki show build attack test shell down clean
