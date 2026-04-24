use anyhow::{Context, Result};
use tun::AbstractDevice;

pub struct TunConfig {
    pub name: Option<String>,
    pub mtu: u32,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    #[allow(dead_code)]
    pub setup_addresses: bool,
}

pub fn create_tun(cfg: &TunConfig) -> Result<tun::Device> {
    let mut tun_cfg = tun::Configuration::default();

    tun_cfg.layer(tun::Layer::L3);

    #[cfg(target_os = "linux")]
    if let Some(ref name) = cfg.name {
        tun_cfg.tun_name(name);
    }

    #[cfg(target_os = "linux")]
    tun_cfg.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    #[cfg(target_os = "windows")]
    let name = match &cfg.name {
        Some(name) => name.clone(),
        None => "usque-rs".to_string(),
    };

    #[cfg(target_os = "windows")]
    tun_cfg.tun_name(name.clone());

    #[cfg(target_os = "windows")]
    tun_cfg.platform_config(move |p| {
        p.wintun_file("wintun.dll");

        if let Ok(guid) = guid_from_name(name) {
            p.device_guid(guid);
        }
    });

    let dev = tun::create(&tun_cfg).context("failed to create TUN device")?;

    log::info!(
        "TUN device created: {}",
        dev.tun_name().unwrap_or_else(|_| "unknown".into())
    );
    Ok(dev)
}

#[cfg(target_os = "linux")]
pub async fn configure_tun(cfg: &TunConfig, dev: &tun::Device) -> Result<()> {
    use futures::stream::TryStreamExt;

    let tun_name = dev
        .tun_name()
        .context("failed to get TUN device name")?
        .clone();

    let (connection, handle, _) =
        rtnetlink::new_connection().context("failed to create netlink connection")?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(tun_name.clone()).execute();
    let link = links
        .try_next()
        .await
        .context("failed to query link")?
        .context("TUN device not found via netlink")?;
    let link_index = link.header.index;

    handle
        .link()
        .set(link_index)
        .mtu(cfg.mtu)
        .execute()
        .await
        .context("failed to set MTU")?;
    log::info!("MTU set to {}", cfg.mtu);

    if let Some(ref ipv4) = cfg.ipv4 {
        let addr: std::net::Ipv4Addr = ipv4.parse().context("invalid IPv4 address in config")?;
        handle
            .address()
            .add(link_index, std::net::IpAddr::V4(addr), 32)
            .execute()
            .await
            .context("failed to add IPv4 address")?;
        log::info!("IPv4 address {addr}/32 added");
    }

    if let Some(ref ipv6) = cfg.ipv6 {
        let addr: std::net::Ipv6Addr = ipv6.parse().context("invalid IPv6 address in config")?;
        handle
            .address()
            .add(link_index, std::net::IpAddr::V6(addr), 128)
            .execute()
            .await
            .context("failed to add IPv6 address")?;
        log::info!("IPv6 address {addr}/128 added");
    }

    handle
        .link()
        .set(link_index)
        .up()
        .execute()
        .await
        .context("failed to bring link up")?;
    log::info!("Link {tun_name} is UP");

    Ok(())
}

#[cfg(target_os = "windows")]
pub async fn configure_tun(cfg: &TunConfig, dev: &tun::Device) -> Result<()> {
    let index = dev.tun_index()? as u32;

    set_mtu_windows(index, cfg.mtu).context("failed to set MTU")?;

    if let Some(ref ipv4) = cfg.ipv4 {
        let ipv4_addr: std::net::IpAddr = ipv4.parse().context("invalid IPv4 address in config")?;

        set_ip_address_windows(index, ipv4_addr).context("failed to set IPv4 address")?;
    }

    if let Some(ref ipv6) = cfg.ipv6 {
        let ipv6_addr: std::net::IpAddr = ipv6.parse().context("invalid IPv6 address in config")?;

        set_ip_address_windows(index, ipv6_addr).context("failed to set IPv6 address")?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn set_mtu_windows(index: u32, mtu: u32) -> Result<()> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry, SetIfEntry, MIB_IFROW};

    unsafe {
        let mut row = MIB_IFROW::default();
        row.dwIndex = index;

        let ret = GetIfEntry(&mut row);
        if ret != 0 {
            anyhow::bail!("failed to get interface entry");
        }

        row.dwMtu = mtu;

        let ret = SetIfEntry(&row);
        if ret != 0 {
            anyhow::bail!("failed to set interface entry");
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn set_ip_address_windows(index: u32, addr: std::net::IpAddr) -> Result<()> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
    };

    unsafe {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = index;
        match addr {
            std::net::IpAddr::V4(ipv4) => {
                row.Address.si_family = windows_sys::Win32::Networking::WinSock::AF_INET as u16;
                row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from(ipv4).to_be();
            }
            std::net::IpAddr::V6(ipv6) => {
                row.Address.si_family = windows_sys::Win32::Networking::WinSock::AF_INET6 as u16;
                row.Address.Ipv6.sin6_addr.u.Byte = ipv6.octets();
            }
        }
        let ret = CreateUnicastIpAddressEntry(&row);
        if ret != 0 {
            anyhow::bail!("failed to create unicast IP address entry");
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn guid_from_name(name: String) -> Result<u128> {
    use boring::hash::{Hasher, MessageDigest};

    let mut hasher = Hasher::new(MessageDigest::md5())?;
    hasher.update(name.as_bytes())?;
    let hash = hasher.finish()?;

    let array: [u8; 16] = hash.to_vec().try_into().expect("Vec must have 16 bytes");

    Ok(u128::from_le_bytes(array))
}
