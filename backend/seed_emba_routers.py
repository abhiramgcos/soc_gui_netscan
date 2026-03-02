import asyncio
import sys

from sqlalchemy import select

sys.path.insert(0, ".")

from app.database import async_session
from app.models.host import Host

ROUTERS = [
    {"ip": "10.0.0.101", "mac": "00:11:22:33:44:a1", "hostname": "Alcatel HH40V", "vendor": "Alcatel", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-alcatel_hh40v-squashfs-factory.bin"},
    {"ip": "10.0.0.102", "mac": "00:11:22:33:44:a2", "hostname": "Alfa Network AP121F", "vendor": "Alfa Network", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-alfa-network_ap121f-squashfs-sysupgrade.bin"},
    {"ip": "10.0.0.103", "mac": "00:11:22:33:44:a3", "hostname": "Alfa Network AP121FE", "vendor": "Alfa Network", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-alfa-network_ap121fe-squashfs-sysupgrade.bin"},
    {"ip": "10.0.0.104", "mac": "00:11:22:33:44:a4", "hostname": "Alfa Network N2Q", "vendor": "Alfa Network", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-alfa-network_n2q-squashfs-sysupgrade.bin"},
    {"ip": "10.0.0.105", "mac": "00:11:22:33:44:a5", "hostname": "Alfa Network N5Q", "vendor": "Alfa Network", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-alfa-network_n5q-squashfs-sysupgrade.bin"},
    {"ip": "10.0.0.106", "mac": "00:11:22:33:44:a6", "hostname": "Alfa Network R36A", "vendor": "Alfa Network", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-alfa-network_r36a-squashfs-sysupgrade.bin"},
    {"ip": "10.0.0.107", "mac": "00:11:22:33:44:a7", "hostname": "Alfa Network Tube-2HQ", "vendor": "Alfa Network", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-alfa-network_tube-2hq-squashfs-sysupgrade.bin"},
    {"ip": "10.0.0.108", "mac": "00:11:22:33:44:a8", "hostname": "Allnet ALL-WAP02860AC", "vendor": "Allnet", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-allnet_all-wap02860ac-squashfs-factory.bin"},
    {"ip": "10.0.0.109", "mac": "00:11:22:33:44:a9", "hostname": "Araknis AN-300-AP-I-N", "vendor": "Araknis", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-araknis_an-300-ap-i-n-squashfs-factory.bin"},
    {"ip": "10.0.0.110", "mac": "00:11:22:33:44:aa", "hostname": "Araknis AN-500-AP-I-AC", "vendor": "Araknis", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-araknis_an-500-ap-i-ac-squashfs-factory.bin"},
    {"ip": "10.0.0.111", "mac": "00:11:22:33:44:ab", "hostname": "Araknis AN-700-AP-I-AC", "vendor": "Araknis", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-araknis_an-700-ap-i-ac-squashfs-factory.bin"},
    {"ip": "10.0.0.112", "mac": "00:11:22:33:44:ac", "hostname": "Arduino Yún", "vendor": "Arduino", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-arduino_yun-squashfs-sysupgrade.bin"},
    {"ip": "10.0.0.113", "mac": "00:11:22:33:44:ad", "hostname": "AVM FRITZ!1750E", "vendor": "AVM", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-avm_fritz1750e-squashfs-sysupgrade.bin"},
    {"ip": "10.0.0.114", "mac": "00:11:22:33:44:ae", "hostname": "Belkin F9J1108 v2", "vendor": "Belkin", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-belkin_f9j1108-v2-squashfs-factory.bin"},
    {"ip": "10.0.0.115", "mac": "00:11:22:33:44:af", "hostname": "Belkin F9K1115 v2", "vendor": "Belkin", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-belkin_f9k1115-v2-squashfs-factory.bin"},
    {"ip": "10.0.0.116", "mac": "00:11:22:33:44:b0", "hostname": "Buffalo BHR-4GRV", "vendor": "Buffalo", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-buffalo_bhr-4grv-squashfs-factory.bin"},
    {"ip": "10.0.0.117", "mac": "00:11:22:33:44:b1", "hostname": "Buffalo WZR-600DHP", "vendor": "Buffalo", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-buffalo_wzr-600dhp-squashfs-factory.bin"},
    {"ip": "10.0.0.118", "mac": "00:11:22:33:44:b2", "hostname": "Buffalo WZR-HP-AG300H", "vendor": "Buffalo", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-buffalo_wzr-hp-ag300h-squashfs-factory.bin"},
    {"ip": "10.0.0.119", "mac": "00:11:22:33:44:b3", "hostname": "Buffalo WZR-HP-G300NH (RB)", "vendor": "Buffalo", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-buffalo_wzr-hp-g300nh-rb-squashfs-factory.bin"},
    {"ip": "10.0.0.120", "mac": "00:11:22:33:44:b4", "hostname": "Buffalo WZR-HP-G450H", "vendor": "Buffalo", "os_name": "OpenWrt", "firmware_url": "https://downloads.openwrt.org/releases/23.05.3/targets/ath79/generic/openwrt-23.05.3-ath79-generic-buffalo_wzr-hp-g450h-squashfs-factory.bin"},
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
