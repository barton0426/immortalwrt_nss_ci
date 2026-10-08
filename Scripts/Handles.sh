#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 VIKINGYFY

FEEDS_PATH="./feeds"
PACKAGE_PATH="./package"

#修补命令统一入口：FIX <名称> <守卫目录> <命令...>
#守卫目录不存在时直接跳过，保证在 bash -e 下不中断
FIX() {
	local NAME=$1
	local GUARD=$2
	shift 2

	[ -d "$GUARD" ] || return 0

	echo " "
	if "$@"; then
		echo "$NAME has been fixed!"
	else
		echo "$NAME fix failed; continuing!"
	fi
}

#修改argon主题字体和颜色
FIX "theme-argon" "$PACKAGE_PATH/luci-theme-argon" sed -i \
	"s/primary '.*'/primary '#31a1a1'/g; s/'0.2'/'0.5'/g; s/'none'/'bing'/g; s/'600'/'normal'/g" \
	"$PACKAGE_PATH/luci-theme-argon/luci-app-argon-config/root/etc/config/argon"

#修改aurora菜单式样
FIX "theme-aurora" "$PACKAGE_PATH/luci-app-aurora-config" find \
	"$PACKAGE_PATH/luci-app-aurora-config/root/usr/share/aurora/" -type f -name '*.template' -exec sed -i \
	"s/nav_type '.*'/nav_type 'dropdown'/g; s/struct_radius_base '.*'/struct_radius_base '0.125rem'/g" {} +

#修改mini-diskmanager菜单位置
FIX "mini-diskmanager" "$PACKAGE_PATH/luci-app-mini-diskmanager" sed -i "s/services/system/g" \
	"$PACKAGE_PATH/luci-app-mini-diskmanager/luci-app-mini-diskmanager/root/usr/share/luci/menu.d/luci-app-mini-diskmanager.json"

#修改natmapt菜单位置
FIX "natmapt" "$PACKAGE_PATH/luci-app-natmapt" sed -i "s/network/services/g" \
	"$PACKAGE_PATH/luci-app-natmapt/root/usr/share/luci/menu.d/luci-app-natmap.json"

#修复Rust编译失败
FIX "rust" "$FEEDS_PATH/packages/lang/rust" sed -i 's/ci-llvm=true/ci-llvm=false/g' \
	"$FEEDS_PATH/packages/lang/rust/Makefile"

#兼容稳定版sing-box：移除1.15专有multi_queue字段（1.14会报unknown field拒绝启动）
HP_GEN="./package/packages/luci-app-homeproxy/root/etc/homeproxy/scripts/generate_client.uc"
if [ -f "$HP_GEN" ]; then
	echo " "
	if sed -i -e 's/^\([ \t]*\)udp_timeout,$/\1udp_timeout/' -e '/^[ \t]*multi_queue$/d' "$HP_GEN"; then
		echo "homeproxy multi_queue field has been removed!"
	else
		echo "homeproxy compat fix failed; continuing!"
	fi
fi

#放行稳定版sing-box：homeproxy 20261008起硬依赖 >=1.15.0_alpha10，实测1.14.2可正常运行(2026-10-08真机A/B)
HP_MK="./package/packages/luci-app-homeproxy/Makefile"
if [ -f "$HP_MK" ]; then
	echo " "
	if sed -i 's/sing-box (>=1\.15\.0_alpha10)/sing-box (>=1.14.2)/' "$HP_MK"; then
		echo "homeproxy sing-box dependency relaxed to 1.14.2!"
	else
		echo "homeproxy dep fix failed; continuing!"
	fi
fi

#移除viking仓库自带的alpha版sing-box，改用feeds稳定版（上游alpha10有本机IPv6劫持bug）
if [ -d "./package/packages/sing-box" ]; then
	rm -rf ./package/packages/sing-box
	echo "viking alpha sing-box removed, feeds stable version will be used!"
fi
