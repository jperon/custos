include $(TOPDIR)/rules.mk

PKG_NAME:=custos
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=CustosVirginum

include $(INCLUDE_DIR)/package.mk

define Package/custos
  SECTION:=net
  CATEGORY:=Network
  TITLE:=CustosVirginum inline DNS filter
  DEPENDS:=+luajit +lyaml +lpeg +nftables +kmod-br-netfilter +kmod-nfnetlink-queue +kmod-nft-queue +wolfssl
  PKGARCH:=all
endef

define Package/custos/description
 CustosVirginum is an inline DNS filter for Linux bridge using NFQUEUE.
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	mkdir -p $(PKG_BUILD_DIR)/lua
	$(CP) /workspace/lua/* $(PKG_BUILD_DIR)/lua/
	$(CP) /workspace/nft-rules/dns-filter-bridge.nft $(PKG_BUILD_DIR)/
endef

define Build/Compile
	true
endef

define Package/custos/conffiles
/etc/config/custos
/etc/custos/config.moon
endef

define Package/custos/install
	$(INSTALL_DIR) $(1)/usr/share/custos
	$(CP) $(PKG_BUILD_DIR)/lua/* $(1)/usr/share/custos/
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/dns-filter-bridge.nft $(1)/usr/share/custos/dns-filter-bridge.nft
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(CURDIR)/files/etc/init.d/custos $(1)/etc/init.d/custos
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(CURDIR)/files/etc/config/custos $(1)/etc/config/custos
	$(INSTALL_DIR) $(1)/etc/custos/lists
	$(INSTALL_CONF) $(CURDIR)/files/etc/custos/config.moon $(1)/etc/custos/config.moon
endef

$(eval $(call BuildPackage,custos))
