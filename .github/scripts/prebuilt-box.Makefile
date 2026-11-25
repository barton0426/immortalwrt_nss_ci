# SPDX-License-Identifier: MIT
# Install a prevalidated static CLI only. No source download, Go helper or service.
# The manual CI caller MUST pass both external absolute paths every time and keep
# them quiescent. It copies this Makefile and private-prebuilt.py into box-private.
include $(TOPDIR)/rules.mk

PKG_NAME:=box-private
PKG_VERSION:=1.15.0_alpha13
PKG_RELEASE:=2
PKG_SOURCE:=
PKG_SOURCE_URL:=
PKG_SOURCE_MIRROR:=0
PKG_BUILD_DIR:=$(BUILD_DIR)/box-private-prebuilt-$(PKG_VERSION)
PKG_LICENSE:=GPL-3.0-or-later MPL-2.0
PKG_BUILD_PARALLEL:=0
PKG_BUILD_DEPENDS:=
PKG_BUILD_FLAGS:=no-mips16

include $(INCLUDE_DIR)/package.mk

# Do not strip or otherwise rewrite the hash-verified prebuilt bytes.
RSTRIP:=:
PRIVATE_PREBUILT_READER:=$(CURDIR)/private-prebuilt.py
# No fallback directory, downloads, public binary, official override or auto-prepare.
# PRIVATE_PREBUILT_INPUT and PRIVATE_PREBUILT_DIR come from the controlled caller.
define PrivatePrebuilt/Check
	test -n "$(PRIVATE_PREBUILT_INPUT)" -a -n "$(PRIVATE_PREBUILT_DIR)"
	python3 "$(PRIVATE_PREBUILT_READER)" check-prepared --buildroot "$(TOPDIR)" --input "$(PRIVATE_PREBUILT_INPUT)" --prepared "$(PRIVATE_PREBUILT_DIR)"
endef

define Package/box-private
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=Unofficial prebuilt private CLI (no service)
  DEPENDS:=+ca-bundle +kmod-inet-diag +kmod-netlink-diag +kmod-tun +kmod-nft-queue +kmod-nf-conntrack-netlink
endef

define Package/box-private/description
  A separately named, offline-validated static CLI. It does not replace official
  sing-box, provide its package identity, install a service or deploy settings.
endef

define Build/Prepare
	$(call PrivatePrebuilt/Check)
	$(INSTALL_DIR) "$(PKG_BUILD_DIR)"
endef

define Build/Configure
endef

define Build/Compile
	$(call PrivatePrebuilt/Check)
endef

define Package/box-private/install
	$(call PrivatePrebuilt/Check)
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/share/box-private
	$(INSTALL_BIN) "$(PRIVATE_PREBUILT_DIR)/box-private" $(1)/usr/bin/box-private
	$(CP) "$(PRIVATE_PREBUILT_DIR)/licenses" $(1)/usr/share/box-private/
	$(INSTALL_DATA) "$(PRIVATE_PREBUILT_DIR)/LICENSE" "$(PRIVATE_PREBUILT_DIR)/MODIFICATION-NOTICE.md" "$(PRIVATE_PREBUILT_DIR)/SOURCE.json" "$(PRIVATE_PREBUILT_DIR)/PREBUILT-MANIFEST.json" $(1)/usr/share/box-private/
	$(INSTALL_DATA) "$(PRIVATE_PREBUILT_DIR)"/build-info-*.txt "$(PRIVATE_PREBUILT_DIR)"/runtime-evidence-*.json $(1)/usr/share/box-private/
	for evidence in "$(PRIVATE_PREBUILT_DIR)"/private-features-*.json; do test ! -f "$$evidence" || $(INSTALL_DATA) "$$evidence" $(1)/usr/share/box-private/; done
endef

# Intentionally no PROVIDES/CONFLICTS sing-box, CPE, init script or conffiles.
$(eval $(call BuildPackage,box-private))
