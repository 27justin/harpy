use pnet::datalink::{DataLinkReceiver, DataLinkSender, Channel, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::sync::Mutex;
//use bus::{Bus, BusReader};

pub struct Sink {
    network: Mutex<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)>,
    channel: (Mutex<Sender<EthernetPacket<'static>>>, Mutex<Receiver<EthernetPacket<'static>>>),
    bus: (Mutex<spmc::Sender<EthernetPacket<'static>>>, spmc::Receiver<EthernetPacket<'static>>),
    mtu: u16
}

impl Sink {
    pub fn new(interface: &NetworkInterface) -> std::io::Result<Sink> {
        debug!("Trying to create sink on interface {}", interface.name);
        let mut options: pnet::datalink::Config = Default::default();
        options.promiscuous = true;
        let (bus_tx, bus_rx) = spmc::channel();
        let (internal_tx, internal_rx) = channel();
        //
        // Read the MTU from /sys/class/net/{interface}/mtu
        let interface_mtu = std::fs::read_to_string(format!("/sys/class/net/{}/mtu", interface.name)).unwrap().trim().parse::<u16>().unwrap();

        debug!("Opening datalink channel on interface {} with MTU {}", interface.name, interface_mtu);
        Ok(match pnet::datalink::channel(&interface, options)? {
            Channel::Ethernet(tx, rx) => Sink {
                network: Mutex::new((tx, rx)),
                channel: (Mutex::new(internal_tx), Mutex::new(internal_rx)),
                bus: (Mutex::new(bus_tx), bus_rx),
                mtu: interface_mtu
            },
            _ => panic!("'Tis impossible"),
        })
    }
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Add a receiver to the bus channel
    /// Note that this function can NOT be called after the sink has been started
    //pub fn add_rx(&mut self) -> BusReader<EthernetPacket<'static>> {
    pub fn add_rx(&self) -> spmc::Receiver<EthernetPacket<'static>> {
        self.bus.1.clone()
    }
    pub fn send(&self, packet: EthernetPacket<'static>) {
        self.channel.0.lock().unwrap().send(packet).unwrap();
    }
    pub fn run(&self) -> ! {
        let mut network_lock = self.network.lock().unwrap();
        let bus_tx = &mut *self.bus.0.lock().unwrap();
        let packet_rx = &*self.channel.1.lock().unwrap();
        debug!("Spinning up network loop.");
        loop {
            // Pop off a packet from the MPSC channel
            match packet_rx.try_recv() {
                Ok(packet) => {
                    trace!("Dumping packet to network");
                    // Send it to the network
                    match network_lock.0.send_to(&packet.packet(), None) {
                        Some(v) => {
                            if let Err(e) = v {
                                error!("An unexpected error occured. Maybe you have TCP offloading enabled?\n{:#?}", e);
                            }
                        },
                        None => {},
                    }
                },
                Err(spmc::TryRecvError::Disconnected) => {
                    error!("SPMC Channel disconnected");
                }
                _ => {}
            }

            let mut buf = vec![0; self.mtu as usize];
            buf.resize(self.mtu as usize, 1);
            match network_lock.1.next() {
                Ok(packet) => {
                    // Redistribute in bus
                    bus_tx.send(EthernetPacket::owned(packet.to_vec()).unwrap()).unwrap();
                },
                Err(e) => {
                    error!("Error: {}", e);
                }
            }
        }
    }

}
