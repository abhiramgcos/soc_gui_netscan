import asyncio
import sys

from sqlalchemy import select

sys.path.insert(0, ".")

from app.database import async_session
from app.models.host import Host

ROUTERS = [
    # TP-Link
    {"ip": "10.0.0.101", "mac": "00:11:22:33:44:01", "hostname": "archer-c7-v5", "vendor": "TP-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-tplink_archer-c7-v5-squashfs-factory.bin"},
    {"ip": "10.0.0.102", "mac": "00:11:22:33:44:02", "hostname": "archer-a7-v5", "vendor": "TP-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-tplink_archer-a7-v5-squashfs-factory.bin"},
    {"ip": "10.0.0.103", "mac": "00:11:22:33:44:03", "hostname": "archer-c7-v2", "vendor": "TP-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-tplink_archer-c7-v2-squashfs-factory.bin"},
    {"ip": "10.0.0.104", "mac": "00:11:22:33:44:04", "hostname": "tl-wr841n-v13", "vendor": "TP-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-tplink_tl-wr841n-v13-squashfs-factory.bin"},
    {"ip": "10.0.0.105", "mac": "00:11:22:33:44:05", "hostname": "cpe210-v3", "vendor": "TP-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-tplink_cpe210-v3-squashfs-factory.bin"},
    {"ip": "10.0.0.106", "mac": "00:11:22:33:44:06", "hostname": "tl-wr902ac-v3", "vendor": "TP-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-tplink_tl-wr902ac-v3-squashfs-factory.bin"},
    {"ip": "10.0.0.107", "mac": "00:11:22:33:44:07", "hostname": "tl-mr3020-v3", "vendor": "TP-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ramips/mt76x8/openwrt-23.05.3-ramips-mt76x8-tplink_tl-mr3020-v3-squashfs-factory.bin"},
    {"ip": "10.0.0.108", "mac": "00:11:22:33:44:08", "hostname": "tl-wa801nd-v5", "vendor": "TP-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ramips/mt76x8/openwrt-23.05.3-ramips-mt76x8-tplink_tl-wa801nd-v5-squashfs-factory.bin"},
    # Netgear
    {"ip": "10.0.0.111", "mac": "00:11:22:33:44:11", "hostname": "wndr3700-v4", "vendor": "Netgear", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-netgear_wndr3700-v4-squashfs-factory.img"},
    {"ip": "10.0.0.112", "mac": "00:11:22:33:44:12", "hostname": "wndr4300-v1", "vendor": "Netgear", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-netgear_wndr4300-v1-squashfs-factory.img"},
    {"ip": "10.0.0.113", "mac": "00:11:22:33:44:13", "hostname": "r6220", "vendor": "Netgear", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ramips/mt7621/openwrt-23.05.3-ramips-mt7621-netgear_r6220-squashfs-factory.img"},
    {"ip": "10.0.0.114", "mac": "00:11:22:33:44:14", "hostname": "wndr3700-v5", "vendor": "Netgear", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ramips/mt7621/openwrt-23.05.3-ramips-mt7621-netgear_wndr3700-v5-squashfs-factory.img"},
    {"ip": "10.0.0.115", "mac": "00:11:22:33:44:15", "hostname": "r7800", "vendor": "Netgear", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ipq806x/generic/openwrt-23.05.3-ipq806x-generic-netgear_r7800-squashfs-factory.img"},
    # D-Link
    {"ip": "10.0.0.121", "mac": "00:11:22:33:44:21", "hostname": "dir-810l", "vendor": "D-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ramips/mt7620/openwrt-23.05.3-ramips-mt7620-dlink_dir-810l-squashfs-factory.bin"},
    {"ip": "10.0.0.122", "mac": "00:11:22:33:44:22", "hostname": "dir-860l-b1", "vendor": "D-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ramips/mt7621/openwrt-23.05.3-ramips-mt7621-dlink_dir-860l-b1-squashfs-factory.bin"},
    {"ip": "10.0.0.123", "mac": "00:11:22:33:44:23", "hostname": "dir-825-c1", "vendor": "D-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-dlink_dir-825-c1-squashfs-factory.bin"},
    {"ip": "10.0.0.124", "mac": "00:11:22:33:44:24", "hostname": "dir-835-a1", "vendor": "D-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-dlink_dir-835-a1-squashfs-factory.bin"},
    {"ip": "10.0.0.125", "mac": "00:11:22:33:44:25", "hostname": "dwr-116-a1", "vendor": "D-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ramips/mt76x8/openwrt-23.05.3-ramips-mt76x8-dlink_dwr-116-a1-squashfs-factory.bin"},
    {"ip": "10.0.0.126", "mac": "00:11:22:33:44:26", "hostname": "dir-869-a1", "vendor": "D-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-dlink_dir-869-a1-squashfs-factory.bin"},
    {"ip": "10.0.0.127", "mac": "00:11:22:33:44:27", "hostname": "dir-859-a1", "vendor": "D-Link", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-dlink_dir-859-a1-squashfs-factory.bin"},
]

async def seed_routers():
    async with async_session() as db:
        for r in ROUTERS:
            host_query = select(Host).where(Host.mac_address == r["mac"])
            result = await db.execute(host_query)
            existing = result.scalar_one_or_none()
            if not existing:
                host = Host(
                    mac_address=r["mac"],
                    ip_address=r["ip"],
                    hostname=r["hostname"],
                    vendor=r["vendor"],
                    os_name=r["os_name"],
                    firmware_url=r["firmware_url"],
                )
                db.add(host)
                print(f"Added {r['hostname']}")
            else:
                existing.firmware_url = r["firmware_url"]
                print(f"Updated {r['hostname']}")
        
        await db.commit()

async def main():
    print("Seeding 20 routers for EMBA tests...")
    await seed_routers()
    print("Done")

if __name__ == "__main__":
    asyncio.run(main())
