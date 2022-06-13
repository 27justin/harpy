use std::{net::{Ipv4Addr, IpAddr}, sync::Arc};

use pnet::{
    datalink::{MacAddr, NetworkInterface},
    packet::{
        ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes},
        arp::{ArpHardwareTypes, MutableArpPacket, ArpPacket, ArpOperations, ArpOperation},
        Packet,
        MutablePacket
    }
};

use crate::sink::Sink;

pub struct ARPController {
    interface: NetworkInterface,
    spoof_table: Vec<Ipv4Addr>,
    sink: Arc<Sink>
}


impl ARPController {
    pub fn new(interface: NetworkInterface, sink: Arc<Sink>) -> ARPController {
        ARPController {
            interface: interface.clone(),
            spoof_table: Default::default(),
            sink
        }
    }

    pub fn spoof_table(&self) -> &Vec<Ipv4Addr> {
        &self.spoof_table
    }
    pub fn spoof_table_mut(&mut self) -> &mut Vec<Ipv4Addr> {
        &mut self.spoof_table
    }

    pub fn sink(&self) -> &Arc<Sink> {
        &self.sink
    }

    pub(crate) fn build_arp_packet(eth_src: MacAddr, eth_dst: MacAddr, src_mac: MacAddr, src_ip: Ipv4Addr, dst_mac: MacAddr, dst_ip: Ipv4Addr, operation: ArpOperation) -> EthernetPacket<'static> {
        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_source(eth_src);
        ethernet_packet.set_destination(eth_dst);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buf = [0u8; ArpPacket::minimum_packet_size()];
        let mut request = MutableArpPacket::new(&mut arp_buf).unwrap();
        request.set_hardware_type(ArpHardwareTypes::Ethernet);
        request.set_protocol_type(EtherTypes::Ipv4);
        request.set_hw_addr_len(6);
        request.set_proto_addr_len(4);
        request.set_operation(operation);
        request.set_sender_hw_addr(src_mac);
        request.set_sender_proto_addr(src_ip);
        request.set_target_hw_addr(dst_mac);
        request.set_target_proto_addr(dst_ip);

        ethernet_packet.set_payload(request.packet_mut());
        EthernetPacket::owned(ethernet_packet.packet().to_vec()).unwrap()
    }

    pub fn spoof(&mut self, source: Ipv4Addr, source_mac: MacAddr, target: Ipv4Addr, target_mac: MacAddr) -> () {
        let packet = ARPController::build_arp_packet(source_mac, target_mac, source_mac, source, target_mac, target, ArpOperations::Reply);
        self.spoof_table.push(target);
        self.sink.send(packet);
    }

    pub fn resolve_mac(&self, ip: &Ipv4Addr) -> Option<MacAddr> {
        let arp = ARPController::build_arp_packet(self.interface.mac.unwrap(), MacAddr::broadcast(), self.interface.mac.unwrap(), match self.interface.ips[0].ip() { IpAddr::V4(ip) => ip, _ => { return None; }}, MacAddr::zero(), *ip, ArpOperations::Request);
        debug!("Trying to resolve MAC for IP: {}", ip);
        self.sink.send(EthernetPacket::owned(arp.packet().to_vec()).unwrap());
        let listener = self.sink.add_rx();
        let mut packets: usize = 0;

        let mut last = std::time::Instant::now();
        loop {
            packets = packets.overflowing_add(1).0;
            let now = std::time::Instant::now();
            if (now - last).as_millis() > 1250 {
                debug!("No reply, sending new ARP request ({})", packets);
                self.sink.send(EthernetPacket::owned(arp.packet().to_vec()).unwrap());
                last = now;
            }

            let packet = listener.recv().unwrap();
            if packet.get_ethertype() == EtherTypes::Arp {
                if let Some(arp_packet) = ArpPacket::new(packet.payload()) {
                    trace!("Received ARP packet: {:?}", arp_packet);
                    if arp_packet.get_operation() == ArpOperations::Reply && &arp_packet.get_sender_proto_addr() == ip {
                        return Some(arp_packet.get_sender_hw_addr());
                    }
                }
            }
        }
    }


}


