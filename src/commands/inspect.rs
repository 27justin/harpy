use std::{sync::Arc};
use pnet::{
    datalink::{self, NetworkInterface},
};
use crate::{Commands, sink::Sink, engine::{HarpyEngine, types::LuaEthernetPacket}};


pub(crate) fn run(args: crate::Args) {
    match args.command {
        Commands::Inspect {
            interface,
            file
        } => {
            let interface = datalink::interfaces().into_iter().filter(|iface: &NetworkInterface| iface.name == interface).next().unwrap_or_else(|| panic!("No such interface: {}", interface));
            let harpy = HarpyEngine::new();

            let sink = Arc::new(match Sink::new(&interface) { Ok(sink) => sink, Err(e) => { error!("Couldn't start network socket: {:#?}", e); std::process::exit(1); } });

            harpy.context(|ctx| {
                ctx.globals().set("MTU", sink.mtu())?;
                ctx.globals().set("harpy_mode", "inspect")
            }).unwrap();
            harpy.run_file(file).unwrap_or_else(|e| error!("Error in lua-script: {}", e));

            let rx_channel = sink.add_rx();
            let clone = sink.clone();
            std::thread::spawn(move || {
                let sink = clone.clone();
                sink.run()
            });

            loop {
                let packet = rx_channel.recv().unwrap();
                let start = std::time::Instant::now();
                harpy.context(|ctx| {
                    let packet: LuaEthernetPacket = (&packet).into();
                    let g = ctx.globals();

                    if let Ok(on_packet) = g.get::<_, rlua::Function>("on_packet") {
                        on_packet.call::<LuaEthernetPacket, Option<LuaEthernetPacket>>(packet)
                            .unwrap_or_else(|e| { error!("on_packet: {}", e); None });
                    }
                });
                trace!("lua - Packet processed in {}ms", start.elapsed().as_millis());


            }
        },
        _ => {}
    }
}


