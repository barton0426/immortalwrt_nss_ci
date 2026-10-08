#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 VIKINGYFY

#移除luci-app-attendedsysupgrade
find ./feeds/luci/collections/ -type f -name "Makefile" -exec sed -i "/attendedsysupgrade/d" {} +
#修改默认主题
find ./feeds/luci/collections/ -type f -name "Makefile" -exec sed -i "s/luci-theme-bootstrap/luci-theme-$WRT_THEME/g" {} +
#修改immortalwrt.lan关联IP
find ./feeds/luci/modules/luci-mod-system/ -type f -name "flash.js" -exec sed -i "s/192\.168\.[0-9]*\.[0-9]*/$WRT_IP/g" {} +
#添加编译日期标识
find ./feeds/luci/modules/luci-mod-status/ -type f -name "10_system.js" -exec sed -i "s/(\(luciversion || ''\))/(\1) + (' \/ $WRT_MARK-$WRT_DATE')/g" {} +

WIFI_UC="./package/network/config/wifi-scripts/files/lib/wifi/mac80211.uc"
if [ -f "$WIFI_UC" ]; then
	#修改WIFI名称
	sed -i "s/ssid='.*'/ssid='$WRT_SSID'/g" $WIFI_UC
	#修改WIFI密码
	sed -i "s/key='.*'/key='$WRT_WORD'/g" $WIFI_UC
fi

CFG_FILE="./package/base-files/files/bin/config_generate"
#修改默认IP地址
sed -i "s/192\.168\.[0-9]*\.[0-9]*/$WRT_IP/g" $CFG_FILE
#修改默认主机名
sed -i "s/hostname='.*'/hostname='$WRT_NAME'/g" $CFG_FILE

#配置文件修改
# 注意：luci / luci-light 等 meta 包在 owrt 分支上会被
# make defconfig 静默丢弃，只能显式声明所有核心组件
echo "CONFIG_PACKAGE_luci-base=y" >> ./.config
echo "CONFIG_PACKAGE_luci-mod-admin-full=y" >> ./.config
echo "CONFIG_PACKAGE_luci-mod-network=y" >> ./.config
echo "CONFIG_PACKAGE_luci-mod-status=y" >> ./.config
echo "CONFIG_PACKAGE_luci-mod-system=y" >> ./.config
echo "CONFIG_PACKAGE_luci-app-firewall=y" >> ./.config
echo "CONFIG_PACKAGE_luci-proto-ppp=y" >> ./.config
echo "CONFIG_PACKAGE_luci-proto-ipv6=y" >> ./.config
echo "CONFIG_PACKAGE_luci-theme-bootstrap=y" >> ./.config
echo "CONFIG_PACKAGE_rpcd-mod-rrdns=y" >> ./.config
echo "CONFIG_PACKAGE_uhttpd=y" >> ./.config
echo "CONFIG_PACKAGE_uhttpd-mod-ubus=y" >> ./.config
echo "CONFIG_LUCI_LANG_zh_Hans=y" >> ./.config
echo "CONFIG_PACKAGE_luci-theme-$WRT_THEME=y" >> ./.config
echo "CONFIG_PACKAGE_luci-app-$WRT_THEME-config=y" >> ./.config

#引入私有扩展配置
if [ -f "$GITHUB_WORKSPACE/Config/PRIVATE.txt" ]; then
	echo "Applying private configurations from PRIVATE.txt..."
	cat $GITHUB_WORKSPACE/Config/PRIVATE.txt >> ./.config
fi

#手动调整的插件
if [ -n "$WRT_PACKAGE" ]; then
	echo -e "$WRT_PACKAGE" >> ./.config
fi

#ARMSR平台调整 - 移除kmod-thunderx-net（上游package定义已删除，但Device/Packages仍引用）
if [[ "${WRT_TARGET^^}" == *"ARMSR"* ]]; then
	sed -i 's/ $(if $(CONFIG_aarch64),kmod-thunderx-net)//' ./target/linux/armsr/image/Makefile
fi

#高通平台调整
DTS_PATH="./target/linux/qualcommax/dts/"
if [[ "${WRT_TARGET^^}" == *"QUALCOMMAX"* ]]; then
	#无WIFI配置调整Q6大小
	if [[ "$WRT_WIFI" == "WIFI-NO" ]]; then
		find $DTS_PATH -type f ! -iname '*nowifi*' -exec sed -i 's/ipq\(6018\|8074\).dtsi/ipq\1-nowifi.dtsi/g' {} +
		echo "qualcommax set up nowifi successfully!"
	fi
fi
