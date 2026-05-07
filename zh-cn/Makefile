include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-xray-zh-cn
PKG_VERSION:=3.7.1
PKG_RELEASE:=3

PKG_LICENSE:=MPLv2
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=yichya <mail@yichya.dev>
PKG_BUILD_PARALLEL:=1
PKGARCH:=all

PO2LMO:=$(firstword $(wildcard $(STAGING_DIR_HOST)/bin/po2lmo) $(wildcard $(STAGING_DIR_HOSTPKG)/bin/po2lmo))

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=Custom
	CATEGORY:=Extra packages
	TITLE:=Simplified Chinese translation for LuCI Xray
	DEPENDS:=luci-app-xray +luci-app-xray-status +luci-app-xray-geodata
	PKGARCH:=all
endef

define Package/$(PKG_NAME)/description
	Simplified Chinese translation package for LuCI Xray.
endef

define Build/Compile
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	test -x "$(PO2LMO)" || (echo "po2lmo not found under STAGING_DIR_HOST/STAGING_DIR_HOSTPKG" && exit 1)
	$(PO2LMO) ./po/zh_Hans/xray.po $(PKG_BUILD_DIR)/xray.zh-cn.lmo
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache
fi
exit 0
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/xray.zh-cn.lmo $(1)/usr/lib/lua/luci/i18n/xray.zh-cn.lmo
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
